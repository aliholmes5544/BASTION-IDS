"""
IDS Version 2 — Training Pipeline
==================================
ML-Based Network Intrusion Detection System
Dataset  : CIC-IDS2017
Models   : Random Forest | XGBoost | MLP Neural Network
Metric   : Macro F1-Score (handles class imbalance correctly)
"""

# ── Python 3.13 WMI workaround ────────────────────────────────
# platform._wmi_query() hangs when WMI service is unresponsive,
# blocking scipy/sklearn imports. Patch before any ML imports.
import platform as _platform
_platform.system  = lambda: "Windows"
_platform.machine = lambda: "AMD64"

import os
import glob
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.ensemble       import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing  import LabelEncoder, StandardScaler, label_binarize
from sklearn.pipeline       import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.metrics import (
    f1_score, accuracy_score, classification_report,
    confusion_matrix, roc_auc_score, roc_curve, auc,
)
from xgboost import XGBClassifier
from imblearn.over_sampling   import SMOTE, RandomOverSampler
from imblearn.under_sampling  import RandomUnderSampler
from tqdm import tqdm

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────
def _has_data_files(d):
    return os.path.isdir(d) and any(
        f.endswith(('.csv', '.parquet')) for f in os.listdir(d)
    )
# Default data directory: use DATA_DIR env var if set, otherwise fall back to data/ next to this script.
_env_data = os.environ.get('BASTION_DATA_DIR', '')
DATA_DIR = _env_data if (_env_data and _has_data_files(_env_data)) else os.path.join(os.path.dirname(__file__), "data")
MODEL_DIR    = os.path.join(os.path.dirname(__file__), "models")
OUTPUT_DIR   = os.path.join(os.path.dirname(__file__), "outputs")
N_FEATURES      = 70        # top features kept after selection
SMOTE_TARGET    = 80_000    # minority classes oversampled to this count
SMOTE_MAX_NATURAL = 10_000  # classes already above this count are NOT SMOTEd
MAJORITY_CAP    = 250_000   # majority class downsampled to this count


# ═════════════════════════════════════════════════════════════
# A. DATA LOADING
# ═════════════════════════════════════════════════════════════

def load_raw_data(data_dir: str = DATA_DIR) -> pd.DataFrame:
    """Glob all CSV and Parquet files, concatenate vertically."""
    # Metadata columns present in original CIC-IDS2017 CSVs — not features
    META_COLS = {'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp'}

    csv_files     = glob.glob(os.path.join(data_dir, "*.csv"))
    parquet_files = glob.glob(os.path.join(data_dir, "*.parquet"))
    all_files     = csv_files + parquet_files

    if not all_files:
        raise FileNotFoundError(
            f"No CSV or Parquet files found in '{data_dir}'.\n"
            "Copy CIC-IDS2017 files into the data/ folder."
        )

    print(f"  Found {len(csv_files)} CSV + {len(parquet_files)} Parquet files")

    frames = []
    for path in all_files:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".parquet":
            df_tmp = pd.read_parquet(path)
        else:
            try:
                df_tmp = pd.read_csv(path, low_memory=False, encoding='utf-8')
            except UnicodeDecodeError:
                df_tmp = pd.read_csv(path, low_memory=False, encoding='latin-1')
        # Strip column name whitespace
        df_tmp.columns = df_tmp.columns.str.strip()
        # Drop metadata columns if present
        drop_cols = [c for c in df_tmp.columns if c in META_COLS]
        if drop_cols:
            df_tmp.drop(columns=drop_cols, inplace=True)
        print(f"  Loaded {os.path.basename(path)}: {len(df_tmp):,} rows × {len(df_tmp.columns)} cols")
        frames.append(df_tmp)

    df = pd.concat(frames, ignore_index=True)
    print(f"\n  Total rows loaded: {len(df):,}")
    return df


# ═════════════════════════════════════════════════════════════
# B. DATA CLEANING
# ═════════════════════════════════════════════════════════════

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleaning steps (in strict order to prevent leakage):
      1. Strip whitespace from column names  (fixes ' Flow Bytes/s' etc.)
      2. Replace ±inf → NaN
      3. Drop rows where Label is NaN
      4. Drop exact duplicate rows
      5. Median-fill remaining NaN in numeric columns
    """
    df = df.copy()

    # 1. Fix column name whitespace
    df.columns = df.columns.str.strip()

    # 2. Replace infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 3. Drop missing labels
    before = len(df)
    df.dropna(subset=["Label"], inplace=True)
    print(f"  Removed {before - len(df):,} rows with missing Label")

    # 4. Drop duplicates
    before = len(df)
    df.drop_duplicates(inplace=True)
    print(f"  Removed {before - len(df):,} duplicate rows")

    # 5. Median-fill NaN
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())
    print(f"  Remaining NaN: {df.isnull().sum().sum()}")
    print(f"  Final shape  : {df.shape}")
    return df


# ═════════════════════════════════════════════════════════════
# C. LABEL ENCODING
# ═════════════════════════════════════════════════════════════

def encode_labels(df: pd.DataFrame):
    """Encode 'Label' column with LabelEncoder."""
    le = LabelEncoder()
    df = df.copy()
    df["Label_encoded"] = le.fit_transform(df["Label"])

    print("\n  Class distribution:")
    counts = df.groupby(["Label", "Label_encoded"]).size().reset_index(name="count")
    for _, row in counts.sort_values("count", ascending=False).iterrows():
        print(f"    [{int(row['Label_encoded']):2d}] {row['Label']:<40s} {int(row['count']):>10,}")

    return df, le


# ═════════════════════════════════════════════════════════════
# D. TRAIN / VAL / TEST SPLIT  —  70 / 15 / 15
# ═════════════════════════════════════════════════════════════

def split_data(df: pd.DataFrame, feature_cols: list):
    """Stratified 70 / 15 / 15 split."""
    X = df[feature_cols].values
    y = df["Label_encoded"].values

    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42
    )

    print(f"\n  Split → train={len(y_train):,}  val={len(y_val):,}  test={len(y_test):,}")
    return X_train, X_val, X_test, y_train, y_val, y_test


# ═════════════════════════════════════════════════════════════
# E. FEATURE SELECTION
# ═════════════════════════════════════════════════════════════

def select_features(
    X_train: np.ndarray,
    y_train: np.ndarray,
    feature_names: list,
    n: int = N_FEATURES,
) -> list:
    """
    Rank features by Gini importance using a shallow RF fitted on a
    40% stratified subsample of training data — balances speed vs. quality.
    Using 40% (up from 20%) gives a more stable feature ranking, especially
    for rare classes that are underrepresented in small subsamples.
    """
    print(f"\n  Selecting top {n} features via shallow RF …")
    idx = np.random.RandomState(42).choice(
        len(X_train), size=int(0.40 * len(X_train)), replace=False
    )
    rf_sel = RandomForestClassifier(
        n_estimators=200, max_depth=None, n_jobs=-1, random_state=42
    )
    rf_sel.fit(X_train[idx], y_train[idx])

    ranked   = np.argsort(rf_sel.feature_importances_)[::-1][:n]
    selected = [feature_names[i] for i in ranked]
    print(f"  Top 5: {selected[:5]}")
    return selected


# ═════════════════════════════════════════════════════════════
# F. PREPROCESSING PIPELINE
# ═════════════════════════════════════════════════════════════

def build_preprocessor() -> Pipeline:
    return Pipeline([("scaler", StandardScaler())])


# ═════════════════════════════════════════════════════════════
# G. CLASS IMBALANCE — SMOTE WITH CAPS
# ═════════════════════════════════════════════════════════════

def apply_smote(
    X_train: np.ndarray,
    y_train: np.ndarray,
    smote_target: int = SMOTE_TARGET,
    majority_cap: int = MAJORITY_CAP,
    smote_max_natural: int = SMOTE_MAX_NATURAL,
):
    """
    Three-stage resampling:
      1. Downsample the dominant majority class to majority_cap
      2. RandomOverSampler for classes with < 6 samples (SMOTE minimum)
      3. Selective SMOTE — only oversample true minority classes (< smote_max_natural).
         Classes already above this threshold (e.g. DoS Hulk, DDoS) are left untouched
         to avoid distorting their natural feature distribution.
    """
    unique, counts = np.unique(y_train, return_counts=True)
    class_counts   = dict(zip(unique.tolist(), counts.tolist()))

    print("\n  Class counts before resampling:")
    for cls, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"    Class {cls}: {cnt:,}")

    # Stage 1 — downsample majority
    majority_cls = max(class_counts, key=class_counts.get)
    if class_counts[majority_cls] > majority_cap:
        print(f"\n  Downsampling class {majority_cls}: {class_counts[majority_cls]:,} → {majority_cap:,}")
        rus = RandomUnderSampler(sampling_strategy={majority_cls: majority_cap}, random_state=42)
        X_train, y_train = rus.fit_resample(X_train, y_train)
        unique, counts   = np.unique(y_train, return_counts=True)
        class_counts     = dict(zip(unique.tolist(), counts.tolist()))

    # Stage 2 — RandomOverSampler for tiny classes (< 6 samples)
    MIN_SMOTE = 6
    tiny_strategy = {c: MIN_SMOTE for c, n in class_counts.items() if n < MIN_SMOTE}
    if tiny_strategy:
        print(f"\n  RandomOverSampler for tiny classes: {list(tiny_strategy)}")
        ros = RandomOverSampler(sampling_strategy=tiny_strategy, random_state=42)
        X_train, y_train = ros.fit_resample(X_train, y_train)
        unique, counts   = np.unique(y_train, return_counts=True)
        class_counts     = dict(zip(unique.tolist(), counts.tolist()))

    # Stage 3 — Selective SMOTE (only true minority classes)
    smote_strategy = {
        c: smote_target
        for c, n in class_counts.items()
        if n < smote_target and n <= smote_max_natural
    }
    skipped = [c for c, n in class_counts.items() if n > smote_max_natural and n < smote_target]
    if skipped:
        print(f"\n  Skipping SMOTE for large classes (>{smote_max_natural:,} natural samples): {skipped}")
    if smote_strategy:
        k = max(1, min(5, min(class_counts[c] for c in smote_strategy) - 1))
        print(f"\n  SMOTE (k={k}, target={smote_target:,}/class) for {len(smote_strategy)} minority classes …")
        smote = SMOTE(sampling_strategy=smote_strategy, k_neighbors=k, random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)

    unique, counts = np.unique(y_train, return_counts=True)
    print(f"\n  After resampling: {len(y_train):,} samples across {len(unique)} classes")
    return X_train, y_train


# ═════════════════════════════════════════════════════════════
# H. MODEL TRAINING
# ═════════════════════════════════════════════════════════════

def train_random_forest(X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    """Random Forest — Baseline Model 1."""
    print("\n[RF] Training Random Forest …")
    t0    = time.time()
    model = RandomForestClassifier(
        n_estimators=600,
        max_depth=None,            # fully grown trees — better for rare classes
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced_subsample",  # per-tree reweighting
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X, y)
    print(f"  Done in {time.time() - t0:.1f}s")
    return model


def compute_sample_weights(y: np.ndarray) -> np.ndarray:
    """Balanced sample weights: w_i = n_samples / (n_classes * count[class_i])."""
    unique, counts = np.unique(y, return_counts=True)
    n_samples  = len(y)
    n_classes  = len(unique)
    weight_map = {c: n_samples / (n_classes * cnt) for c, cnt in zip(unique, counts)}
    return np.array([weight_map[yi] for yi in y])


def train_xgboost(
    X: np.ndarray, y: np.ndarray, n_classes: int,
    X_val: np.ndarray = None, y_val: np.ndarray = None,
) -> XGBClassifier:
    """
    XGBoost — Primary Model.
    Key changes vs. previous version:
      - n_estimators 300→700, learning_rate 0.1→0.05  (more, slower steps)
      - max_depth 8→10  (capture finer decision boundaries)
      - min_child_weight=3  (prevents overfitting on tiny SMOTE clusters)
      - early stopping on val set to find optimal n_estimators automatically
    """
    print("\n[XGB] Training XGBoost …")
    t0    = time.time()
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=n_classes,
        tree_method="hist",
        n_estimators=1000,
        learning_rate=0.03,
        max_depth=12,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        n_jobs=-1,
        random_state=42,
        eval_metric="mlogloss",
        verbosity=0,
        early_stopping_rounds=40 if X_val is not None else None,
    )
    sample_weight = compute_sample_weights(y)
    fit_kwargs = dict(sample_weight=sample_weight)
    if X_val is not None:
        fit_kwargs["eval_set"] = [(X_val, y_val)]
        fit_kwargs["verbose"]  = False
    model.fit(X, y, **fit_kwargs)
    best = getattr(model, "best_iteration", None)
    print(f"  Done in {time.time() - t0:.1f}s"
          + (f"  (best iter={best})" if best else ""))
    return model


def train_mlp(X: np.ndarray, y: np.ndarray) -> MLPClassifier:
    """
    MLP Neural Network — Advanced Model.
    Architecture : 512 → 256 → 128 → 64 → softmax
    Solver       : Adam
    Regularisation: early stopping on 10% validation split
    """
    print("\n[MLP] Training Neural Network (MLP) …")
    print("  Architecture : Input → 512 → 256 → 128 → 64 → Output")
    print("  Activation   : ReLU")
    print("  Solver       : Adam  |  Early stopping: ON")
    t0    = time.time()
    model = MLPClassifier(
        hidden_layer_sizes=(512, 256, 128, 64),
        activation="relu",
        solver="adam",
        learning_rate_init=0.0005,
        max_iter=200,
        batch_size=256,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20,
        random_state=42,
        verbose=False,
    )
    model.fit(X, y)
    print(f"  Done in {time.time() - t0:.1f}s  (epochs={model.n_iter_})")
    return model


def train_ensemble(rf_model, xgb_model) -> VotingClassifier:
    """
    Soft-voting ensemble of the already-trained RF and XGBoost models.
    Averaging their predicted probabilities almost always beats either
    model alone, especially on rare classes where one model is more
    confident than the other.
    XGBoost gets 2× weight since it typically has the higher F1.
    """
    from sklearn.preprocessing import LabelEncoder as _LE
    print("\n[ENS] Building soft-voting ensemble (RF + XGBoost) …")
    ensemble = VotingClassifier(
        estimators=[("rf", rf_model), ("xgb", xgb_model)],
        voting="soft",
        weights=[1, 3],
    )
    # VotingClassifier.fit() would re-train from scratch — instead we
    # mark it as already fitted by setting the sub-estimator list directly.
    # le_ is used by predict() to inverse-transform the winning class index.
    classes = rf_model.classes_
    le = _LE()
    le.fit(classes)
    ensemble.estimators_ = [rf_model, xgb_model]
    ensemble.le_         = le
    ensemble.classes_    = classes
    print("  Ensemble ready (no re-training needed).")
    return ensemble


# ═════════════════════════════════════════════════════════════
# H2. THRESHOLD TUNING
# ═════════════════════════════════════════════════════════════

class ThresholdClassifier:
    """
    Wraps any predict_proba model and applies per-class probability scale
    factors before argmax.  Dividing class i's probability column by scale[i]
    is equivalent to requiring class i to be scale[i] times more confident
    before it wins.  scale > 1 raises the bar (reduces over-prediction),
    scale < 1 lowers it (helps under-predicted rare classes).
    Optimised on the validation set to maximise macro F1.
    """
    def __init__(self, base_model, scales, int_classes):
        self.base_model  = base_model
        self.scales      = np.asarray(scales, dtype=float)
        self.classes_    = int_classes          # integer class indices

    def predict(self, X):
        proba  = self.base_model.predict_proba(X)
        scaled = proba / self.scales
        return self.classes_[np.argmax(scaled, axis=1)]

    def predict_proba(self, X):
        return self.base_model.predict_proba(X)


def optimize_thresholds(model, X_val, y_val, n_classes, label_encoder=None):
    """
    Greedy per-class scale-factor search on the validation set.
    Sweeps scale ∈ [0.10, 4.0] in 0.02 steps for each class independently,
    keeping whichever value improves macro F1. Runs 4 refinement passes.

    Scale constraint: large, well-represented classes (DDoS, DoS Hulk) are
    given a minimum scale floor of 0.5 to prevent the tuner from making them
    so dominant that they absorb borderline flows in real-world scans.
    """
    # Classes that must not have their scale drop below SCALE_FLOOR
    SCALE_FLOOR = 0.5
    LARGE_CLASS_NAMES = {'DDoS', 'DoS Hulk'}
    large_class_indices = set()
    if label_encoder is not None:
        for i, name in enumerate(label_encoder.classes_):
            if name in LARGE_CLASS_NAMES:
                large_class_indices.add(i)
        if large_class_indices:
            print(f"\n  Scale floor {SCALE_FLOOR} applied to classes: "
                  f"{[label_encoder.classes_[i] for i in sorted(large_class_indices)]}")

    proba = model.predict_proba(X_val)
    scales = np.ones(n_classes)

    def score(s):
        preds = np.argmax(proba / s, axis=1)
        return f1_score(y_val, preds, average="macro", zero_division=0)

    base_f1 = score(scales)
    print(f"\n  Baseline macro F1 (pre-tuning) : {base_f1:.4f}")

    sweep = np.round(np.arange(0.10, 4.05, 0.02), 3)

    for pass_num in range(4):
        improved = 0
        for cls_idx in range(n_classes):
            # Apply minimum scale floor for large classes
            floor = SCALE_FLOOR if cls_idx in large_class_indices else 0.10
            allowed = sweep[sweep >= floor]
            best_f1 = score(scales)
            best_s  = scales[cls_idx]
            for s in allowed:
                trial = scales.copy()
                trial[cls_idx] = s
                f = score(trial)
                if f > best_f1 + 1e-6:
                    best_f1 = f
                    best_s  = s
            if scales[cls_idx] != best_s:
                improved += 1
            scales[cls_idx] = best_s
        print(f"  Pass {pass_num + 1}: {improved} classes adjusted  →  macro F1={score(scales):.4f}")

    tuned_f1 = score(scales)
    print(f"  After threshold tuning macro F1: {tuned_f1:.4f}")
    print(f"  Scales: {np.round(scales, 2).tolist()}")
    return scales


# ═════════════════════════════════════════════════════════════
# I. EVALUATION
# ═════════════════════════════════════════════════════════════

def evaluate_model(
    model,
    X: np.ndarray,
    y_true: np.ndarray,
    label_encoder: LabelEncoder,
    split_name: str,
    output_dir: str = OUTPUT_DIR,
) -> dict:
    """
    Compute Macro F1, Weighted F1, Accuracy, ROC-AUC.
    Save confusion matrix and ROC curves to output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)
    tag         = type(model).__name__
    class_names = label_encoder.classes_

    y_pred      = model.predict(X)
    macro_f1    = f1_score(y_true, y_pred, average="macro",    zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    acc         = accuracy_score(y_true, y_pred)

    try:
        y_prob  = model.predict_proba(X)
        n_cls   = len(class_names)
        y_bin   = label_binarize(y_true, classes=np.arange(n_cls))
        present = np.unique(y_true)
        roc_auc = roc_auc_score(
            y_bin[:, present], y_prob[:, present],
            average="macro", multi_class="ovr",
        )
    except Exception:
        roc_auc = float("nan")
        y_prob  = None

    print(f"\n  [{tag}] {split_name}")
    print(f"    Macro F1    : {macro_f1:.4f}")
    print(f"    Weighted F1 : {weighted_f1:.4f}")
    print(f"    Accuracy    : {acc:.4f}")
    print(f"    ROC-AUC     : {roc_auc:.4f}" if not np.isnan(roc_auc) else "    ROC-AUC     : N/A")

    # ── Confusion Matrix ──────────────────────────────────────
    cm  = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(16, 14))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names, ax=ax)
    ax.set_title(f"Confusion Matrix — {tag} ({split_name})", fontsize=14)
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_ylabel("True", fontsize=12)
    plt.xticks(rotation=45, ha="right", fontsize=8)
    plt.tight_layout()
    cm_path = os.path.join(output_dir, f"confusion_matrix_{split_name}_{tag}.png")
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"    Confusion matrix → {cm_path}")

    # ── ROC Curves ───────────────────────────────────────────
    if y_prob is not None:
        n_cls = len(class_names)
        y_bin = label_binarize(y_true, classes=np.arange(n_cls))
        fig, ax = plt.subplots(figsize=(14, 10))
        colors  = plt.cm.tab20.colors
        for i, name in enumerate(class_names):
            if i < y_bin.shape[1] and y_bin[:, i].sum() > 0:
                fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
                ax.plot(fpr, tpr, color=colors[i % len(colors)], lw=1.5,
                        label=f"{name} (AUC={auc(fpr, tpr):.2f})")
        ax.plot([0, 1], [0, 1], "k--", lw=1)
        ax.set_xlabel("False Positive Rate", fontsize=12)
        ax.set_ylabel("True Positive Rate",  fontsize=12)
        ax.set_title(f"ROC Curves — {tag} ({split_name})", fontsize=14)
        ax.legend(loc="lower right", fontsize=7, ncol=2)
        plt.tight_layout()
        roc_path = os.path.join(output_dir, f"roc_curves_{split_name}_{tag}.png")
        fig.savefig(roc_path, dpi=150)
        plt.close(fig)
        print(f"    ROC curves     → {roc_path}")

    clean_names = [n.encode('ascii', 'replace').decode('ascii').replace('?', ' ').strip() for n in class_names]
    report = classification_report(y_true, y_pred, target_names=clean_names, zero_division=0)
    print("\n  Classification Report:")
    for line in report.split("\n"):
        print("    " + line)

    return {
        "model": tag, "split": split_name,
        "macro_f1": macro_f1, "weighted_f1": weighted_f1,
        "accuracy": acc, "roc_auc": roc_auc,
        "classification_report": report,
    }


def plot_feature_importance(rf_model, feature_names: list, output_dir: str = OUTPUT_DIR):
    """Top-20 RF feature importance horizontal bar chart."""
    importances = rf_model.feature_importances_
    ranked      = np.argsort(importances)[::-1][:20]
    top_names   = [feature_names[i] for i in ranked]
    top_vals    = importances[ranked]

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(np.arange(len(top_names)), top_vals[::-1], color="steelblue", align="center")
    ax.set_yticks(np.arange(len(top_names)))
    ax.set_yticklabels(top_names[::-1], fontsize=9)
    ax.set_xlabel("Importance", fontsize=11)
    ax.set_title("Top 20 Feature Importances (Random Forest)", fontsize=13)
    plt.tight_layout()
    path = os.path.join(output_dir, "feature_importance.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\n  Feature importance → {path}")


# ═════════════════════════════════════════════════════════════
# J. SAVE ARTIFACTS
# ═════════════════════════════════════════════════════════════

def save_artifacts(
    best_model, rf_model, xgb_model, mlp_model, ensemble_model, tuned_model,
    preprocessor, label_encoder, feature_names,
    model_dir: str = MODEL_DIR,
):
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(best_model,      os.path.join(model_dir, "best_model.pkl"))
    joblib.dump(rf_model,        os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(xgb_model,       os.path.join(model_dir, "xgb_model.pkl"))
    joblib.dump(mlp_model,       os.path.join(model_dir, "mlp_model.pkl"))
    joblib.dump(ensemble_model,  os.path.join(model_dir, "ensemble_model.pkl"))
    joblib.dump(tuned_model,     os.path.join(model_dir, "tuned_model.pkl"))
    joblib.dump(preprocessor,    os.path.join(model_dir, "preprocessor.pkl"))
    joblib.dump(label_encoder.classes_, os.path.join(model_dir, "label_encoder.pkl"))
    joblib.dump(feature_names,   os.path.join(model_dir, "feature_names.pkl"))
    print(f"\n  All artifacts saved → '{model_dir}'")


# ═════════════════════════════════════════════════════════════
# K. TRAINING REPORT
# ═════════════════════════════════════════════════════════════

def save_training_report(
    all_val: list,
    best_name: str,
    best_test: dict,
    output_dir: str = OUTPUT_DIR,
):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "training_report.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  IDS Version 2 — Training Report\n")
        f.write("  Models: Random Forest | XGBoost | MLP Neural Network\n")
        f.write("=" * 60 + "\n\n")

        f.write("── Validation Results ──────────────────────────────────\n\n")
        for m in all_val:
            marker = "  ← BEST MODEL" if m["model"] == best_name else ""
            f.write(f"Model: {m['model']}{marker}\n")
            f.write(f"  Macro F1    : {m['macro_f1']:.4f}\n")
            f.write(f"  Weighted F1 : {m['weighted_f1']:.4f}\n")
            f.write(f"  Accuracy    : {m['accuracy']:.4f}\n")
            f.write(f"  ROC-AUC     : {m['roc_auc']:.4f}\n\n")
            f.write("  Classification Report:\n")
            f.write(m["classification_report"])
            f.write("\n\n")

        f.write(f"── Best Model Selected: {best_name} ───────────────────\n\n")
        f.write("── Test Set Results ────────────────────────────────────\n\n")
        f.write(f"  Macro F1    : {best_test['macro_f1']:.4f}\n")
        f.write(f"  Weighted F1 : {best_test['weighted_f1']:.4f}\n")
        f.write(f"  Accuracy    : {best_test['accuracy']:.4f}\n")
        f.write(f"  ROC-AUC     : {best_test['roc_auc']:.4f}\n\n")
        f.write("  Classification Report:\n")
        f.write(best_test["classification_report"])

    print(f"  Training report → {path}")


# ═════════════════════════════════════════════════════════════
# MAIN ORCHESTRATION
# ═════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  IDS Version 2 — Training Pipeline")
    print("  Models: Random Forest | XGBoost | MLP Neural Network")
    print("  Metric: Macro F1-Score")
    print("=" * 60)

    # ── [1/11] Load ───────────────────────────────────────────
    print("\n[1/11] Loading raw data …")
    df = load_raw_data(DATA_DIR)

    # ── [2/11] Clean ──────────────────────────────────────────
    print("\n[2/11] Cleaning data …")
    df = clean_data(df)

    # ── [3/11] Encode labels ──────────────────────────────────
    print("\n[3/11] Encoding labels …")
    df, label_encoder = encode_labels(df)
    n_classes = len(label_encoder.classes_)

    label_cols   = {"Label", "Label_encoded"}
    feature_cols = [
        c for c in df.columns
        if c not in label_cols and pd.api.types.is_numeric_dtype(df[c])
    ]
    print(f"\n  Available numeric features: {len(feature_cols)}")

    # ── [4/11] Split ──────────────────────────────────────────
    print("\n[4/11] Splitting 70 / 15 / 15 …")
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(df, feature_cols)

    # ── [5/11] Feature selection ──────────────────────────────
    print("\n[5/11] Selecting top features …")
    selected = select_features(X_train, y_train, feature_cols, N_FEATURES)
    feat_idx = [feature_cols.index(f) for f in selected]
    X_train_sel = X_train[:, feat_idx]
    X_val_sel   = X_val[:,   feat_idx]
    X_test_sel  = X_test[:,  feat_idx]

    # ── [6/11] Preprocess ─────────────────────────────────────
    print("\n[6/11] Fitting StandardScaler …")
    preprocessor = build_preprocessor()
    X_train_pp   = preprocessor.fit_transform(X_train_sel)
    X_val_pp     = preprocessor.transform(X_val_sel)
    X_test_pp    = preprocessor.transform(X_test_sel)
    print(f"  Shapes → train={X_train_pp.shape}  val={X_val_pp.shape}  test={X_test_pp.shape}")

    # ── [7/11] SMOTE ──────────────────────────────────────────
    print("\n[7/11] Applying SMOTE …")
    X_train_res, y_train_res = apply_smote(X_train_pp, y_train)

    # ── [8/11] Train all models ───────────────────────────────
    print("\n[8/11] Training models …")
    rf_model  = train_random_forest(X_train_res, y_train_res)
    # Pass val set so XGBoost can use early stopping to find best n_estimators
    xgb_model = train_xgboost(X_train_res, y_train_res, n_classes,
                               X_val=X_val_pp, y_val=y_val)
    mlp_model = train_mlp(X_train_res, y_train_res)
    ensemble_model = train_ensemble(rf_model, xgb_model)

    # ── [9/11] Evaluate on validation ─────────────────────────
    print("\n[9/11] Evaluating on validation set …")
    rf_val  = evaluate_model(rf_model,       X_val_pp, y_val, label_encoder, "val")
    xgb_val = evaluate_model(xgb_model,      X_val_pp, y_val, label_encoder, "val")
    mlp_val = evaluate_model(mlp_model,      X_val_pp, y_val, label_encoder, "val")
    ens_val = evaluate_model(ensemble_model, X_val_pp, y_val, label_encoder, "val")

    # ── Threshold tuning on the ensemble (best base model) ────
    print("\n[9b] Tuning per-class thresholds on validation set …")
    scales = optimize_thresholds(ensemble_model, X_val_pp, y_val, n_classes, label_encoder)
    tuned_model = ThresholdClassifier(ensemble_model, scales, ensemble_model.classes_)
    tuned_val   = evaluate_model(tuned_model, X_val_pp, y_val, label_encoder, "val")

    all_val   = [rf_val, xgb_val, mlp_val, ens_val, tuned_val]
    best_val  = max(all_val, key=lambda m: m["macro_f1"])
    best_name = best_val["model"]
    model_map = {
        "RandomForestClassifier": rf_model,
        "XGBClassifier":          xgb_model,
        "MLPClassifier":          mlp_model,
        "VotingClassifier":       ensemble_model,
        "ThresholdClassifier":    tuned_model,
    }
    best_model = model_map[best_name]
    print(f"\n  Best model: {best_name}  (Macro F1={best_val['macro_f1']:.4f})")

    # ── [10/11] Evaluate best on test ─────────────────────────
    print("\n[10/11] Evaluating best model on test set …")
    best_test = evaluate_model(best_model, X_test_pp, y_test, label_encoder, "test")

    # Feature importance chart (always use RF)
    plot_feature_importance(rf_model, selected)

    # ── [11/11] Save ──────────────────────────────────────────
    print("\n[11/11] Saving artifacts …")
    save_artifacts(
        best_model, rf_model, xgb_model, mlp_model, ensemble_model, tuned_model,
        preprocessor, label_encoder, selected,
    )
    save_training_report(all_val, best_name, best_test)

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE — SUMMARY")
    print("=" * 60)
    print(f"\n{'Model':<28} {'Macro F1':>10} {'Weighted F1':>12} {'Accuracy':>10} {'ROC-AUC':>10}")
    print("-" * 74)
    for m in all_val:
        mark = "  ← BEST" if m["model"] == best_name else ""
        print(
            f"  {m['model']:<26} {m['macro_f1']:>10.4f}"
            f" {m['weighted_f1']:>12.4f} {m['accuracy']:>10.4f}"
            f" {m['roc_auc']:>10.4f}{mark}"
        )
    print(f"\n  Test Macro F1 ({best_name}): {best_test['macro_f1']:.4f}")
    print(f"\n  Artifacts → '{MODEL_DIR}'")
    print(f"  Outputs   → '{OUTPUT_DIR}'")
    print("\n  Run dashboard: py app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
