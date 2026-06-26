"""
train_sklearn.py — Tầng 2: RandomForest / SVM Classifier

Train scikit-learn classifier trên labeled.jsonl
→ ghi ra data/training/sklearn_model.pkl

Cách dùng:
    pip install scikit-learn --break-system-packages
    python scripts/train_sklearn.py
    python scripts/train_sklearn.py --model svm --visualize

Kết quả: data/training/sklearn_model.pkl được tải tự động bởi mitre_mapper.py
         nếu file tồn tại (sklearn có độ ưu tiên cao hơn centroid)
"""

import argparse
import json
from collections import Counter
from pathlib import Path

LABELED_PATH  = Path("data/training/labeled.jsonl")
MODEL_OUT     = Path("data/training/sklearn_model.pkl")
REPORT_OUT    = Path("data/training/sklearn_report.txt")

FEATURE_NAMES = [
    "threat_score", "failed_auth", "fw_blocks", "pps",
    "bytes_per_pkt", "sym_ratio", "entropy", "is_tor",
    "anomaly_cnt", "ml_confidence",
]


def load_data(path: Path):
    X, y = [], []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            if obj.get("confirmed", True):
                X.append(obj["feature_vector"])
                y.append(obj["true_label"])
    return X, y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model",     choices=["rf", "svm", "knn"], default="rf",
                        help="rf=RandomForest, svm=SVM, knn=KNeighbors")
    parser.add_argument("--input",     default=str(LABELED_PATH))
    parser.add_argument("--output",    default=str(MODEL_OUT))
    parser.add_argument("--visualize", action="store_true", help="In feature importance (RF only)")
    parser.add_argument("--test-split",type=float, default=0.2, help="Test set ratio (0=không split)")
    args = parser.parse_args()

    try:
        import sklearn
    except ImportError:
        print("[ERROR] scikit-learn chưa cài. Chạy: pip install scikit-learn --break-system-packages")
        return 1

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.model_selection import cross_val_score, train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
    import pickle

    input_path  = Path(args.input)
    output_path = Path(args.output)

    X, y = load_data(input_path)
    if len(X) < 4:
        print(f"[ERROR] Cần ít nhất 4 samples. Hiện có {len(X)}")
        return 1

    print(f"[TRAIN] Loaded {len(X)} samples, {len(set(y))} classes")
    print(f"[TRAIN] Distribution: {dict(Counter(y))}")

    # Label encode
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Build model
    # Custom weights cho các class hay bị nhầm (dùng string key trước)
    _str_weights = {
        "BENIGN":    1.0,
        "T1498":     1.5,
        "T1071.001": 2.5,    # hay bị nhầm với T1595 ← tăng penalty
        "T1595.001": 2.5,    # hay bị nhầm với T1071 ← tăng penalty
        "T1110.001": 2.0,
        "T1041":     2.0,
    }
    # Convert sang int keys sau khi LabelEncoder fit (bên dưới)
    # Dùng "balanced" làm fallback nếu có class chưa map được
    if args.model == "rf":
        clf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=3,
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=42,
            class_weight="balanced",  # placeholder, sẽ override sau khi encode
            n_jobs=-1,
        )
    elif args.model == "svm":
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
        clf = Pipeline([
            ("scaler", StandardScaler()),
            ("svm",    SVC(kernel="rbf", C=10, gamma="scale",
                           class_weight="balanced", probability=True)),
        ])
    else:  # knn
        clf = KNeighborsClassifier(n_neighbors=3, metric="euclidean")

    # Override class_weight với int keys sau khi LabelEncoder fit
    if args.model == "rf" and hasattr(clf, "class_weight"):
        int_weights = {
            le.transform([k])[0]: v
            for k, v in _str_weights.items()
            if k in le.classes_
        }
        clf.set_params(class_weight=int_weights)

    # Cross-validation (nếu đủ samples)
    if len(X) >= 5:
        cv_scores = cross_val_score(clf, X, y_enc, cv=min(5, len(X)), scoring="accuracy")
        print(f"[TRAIN] Cross-val accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    else:
        print("[WARN ] Ít samples — bỏ qua cross-validation")

    # Train/test split
    if args.test_split > 0 and len(X) >= 6:
        X_tr, X_te, y_tr, y_te = train_test_split(X, y_enc, test_size=args.test_split,
                                                    random_state=42, stratify=y_enc)
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)
        report_str = classification_report(y_te, y_pred, target_names=le.classes_)
        print("\n" + "="*55)
        print("Classification Report (test set):")
        print(report_str)
        print("="*55 + "\n")

        # Ghi report ra file .txt
        REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
        REPORT_OUT.write_text(
            f"NIRO — RandomForest Classification Report\n"
            f"Dataset: {args.input}  |  Samples: {len(X)}\n"
            f"{'='*55}\n"
            f"{report_str}",
            encoding="utf-8",
        )
        print(f"[TRAIN] Report saved → {REPORT_OUT}")
    else:
        # Train on all data
        clf.fit(X, y_enc)

    # Feature importance (RandomForest only)
    if args.visualize and args.model == "rf":
        print("Feature Importance (RandomForest):")
        importances = clf.feature_importances_
        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        for name, imp in ranked:
            bar = "█" * int(imp * 40)
            print(f"  {name:<18s} {bar:<40s} {imp:.3f}")
        print()

    # Save model + encoder
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_data = {"model": clf, "label_encoder": le, "feature_names": FEATURE_NAMES,
                  "model_type": args.model, "n_samples": len(X)}
    with output_path.open("wb") as f:
        pickle.dump(model_data, f)

    print(f"[TRAIN] Model saved → {output_path}")
    print(f"[TRAIN] mitre_mapper.py sẽ tự load sklearn model này (ưu tiên hơn centroid)\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
