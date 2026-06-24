"""
Training Isolation Forest untuk Engram
Dataset: CIC-MalMem-2022

Pendekatan: True unsupervised anomaly detection
- Model dilatih HANYA dari data Benign (pola "sehat")
- Label Class dipakai untuk evaluasi performa, BUKAN untuk training
- Ini menjaga filosofi zero-day detection: model tidak pernah "diajari"
  contoh malware secara langsung, hanya belajar mendeteksi penyimpangan
  dari pola normal.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib

# ── 1. LOAD DATASET ──────────────────────────────────────────
print("Loading dataset...")
df = pd.read_parquet('Obfuscated-MalMem2022.parquet')  # sesuaikan path file kamu

print(f"Total records: {len(df)}")
print(df['Class'].value_counts())
print()

# ── 2. PISAHKAN FITUR DAN LABEL ──────────────────────────────
# Drop kolom non-numerik yang tidak relevan untuk model
X = df.drop(columns=['Class', 'Category'], errors='ignore')
y = df['Class']  # 'Benign' atau 'Malware'

feature_names = X.columns.tolist()
print(f"Jumlah fitur: {len(feature_names)}")
print(f"Fitur: {feature_names}")
print()

# ── 3. SPLIT DATA ─────────────────────────────────────────────
# Split dulu jadi train/test, supaya evaluasi nanti fair
# (test set harus benar-benar belum pernah dilihat model)
X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 4. AMBIL HANYA DATA BENIGN UNTUK TRAINING ────────────────
# Ini kunci dari pendekatan unsupervised yang benar:
# Model HANYA boleh belajar dari pola "sehat"
train_benign_mask = y_train_full == 'Benign'
X_train_benign = X_train_full[train_benign_mask]

print(f"Data training (Benign only): {len(X_train_benign)} records")
print(f"Data testing (Benign + Malware): {len(X_test)} records")
print()

# ── 5. NORMALISASI FITUR ──────────────────────────────────────
# Isolation Forest sensitif terhadap skala fitur yang beda-beda jauh
# (misal pslist.nproc range 0-200, tapi malfind.commitCharge bisa jutaan)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_benign)
X_test_scaled = scaler.transform(X_test)

# ── 6. TRAINING MODEL ─────────────────────────────────────────
print("Training Isolation Forest...")

model = IsolationForest(
    n_estimators=200,        # jumlah trees, lebih banyak = lebih stabil
    contamination=0.1,       # estimasi proporsi anomali yang diharapkan
    max_samples='auto',
    random_state=42,
    n_jobs=-1                # pakai semua CPU core
)

model.fit(X_train_scaled)
print("Training selesai.\n")

# ── 7. EVALUASI PERFORMA ──────────────────────────────────────
# decision_function: semakin NEGATIF = semakin dianggap anomali
# predict: -1 = anomali (dianggap malware), 1 = normal (dianggap benign)

predictions = model.predict(X_test_scaled)
anomaly_scores = model.decision_function(X_test_scaled)

# Convert prediksi ke format yang sama dengan label asli untuk dibandingkan
# -1 (anomali) -> 'Malware', 1 (normal) -> 'Benign'
y_pred = np.where(predictions == -1, 'Malware', 'Benign')

print("=" * 50)
print("EVALUASI PERFORMA MODEL")
print("=" * 50)
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred, labels=['Benign', 'Malware']))

# ROC-AUC pakai anomaly score (semakin negatif = semakin malware)
# jadi kita balik tandanya biar score tinggi = malware
y_test_binary = (y_test == 'Malware').astype(int)
auc_score = roc_auc_score(y_test_binary, -anomaly_scores)
print(f"\nROC-AUC Score: {auc_score:.4f}")

# ── 8. CONVERT SCORE KE SKALA 0-100 (untuk dashboard) ────────
def score_to_percentage(raw_score, score_min, score_max):
    """
    Convert decision_function output (biasanya -0.5 s.d 0.5)
    ke skala 0-100 dimana 100 = paling mencurigakan
    """
    normalized = (raw_score - score_min) / (score_max - score_min)
    # Balik karena score negatif = lebih anomali
    percentage = (1 - normalized) * 100
    return np.clip(percentage, 0, 100)

score_min = anomaly_scores.min()
score_max = anomaly_scores.max()

print(f"\nRange anomaly score mentah: {score_min:.4f} s.d {score_max:.4f}")
print("(simpan score_min dan score_max ini untuk konversi saat inference nanti)")

# ── 9. SIMPAN MODEL + SCALER + METADATA ──────────────────────
joblib.dump(model, 'engram_isolation_forest.pkl')
joblib.dump(scaler, 'engram_scaler.pkl')

metadata = {
    'feature_names': feature_names,
    'score_min': float(score_min),
    'score_max': float(score_max),
    'training_samples': len(X_train_benign),
    'auc_score': float(auc_score),
}
joblib.dump(metadata, 'engram_model_metadata.pkl')

print("\nModel tersimpan:")
print("  - engram_isolation_forest.pkl  (model)")
print("  - engram_scaler.pkl            (normalizer fitur)")
print("  - engram_model_metadata.pkl    (info fitur & range score)")
