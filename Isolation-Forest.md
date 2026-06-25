# Memahami Cara Kerja Isolation Forest pada Engram

## Gambaran Umum

Engram menggunakan pendekatan **anomaly detection** berbasis **Isolation Forest** untuk mendeteksi proses yang mencurigakan berdasarkan karakteristik memori.

Berbeda dengan antivirus tradisional yang belajar mengenali malware tertentu, model ini hanya belajar dari contoh sistem yang sehat (*benign*).

Filosofinya sederhana:

> Jika kita tahu seperti apa perilaku normal sebuah sistem, maka kita dapat mendeteksi sesuatu yang menyimpang dari normalitas tersebut.

---

# Paradigma yang Digunakan

Sebagian besar model klasifikasi malware bekerja seperti berikut:

```text
Training:
    Benign
    Malware A
    Malware B
    Malware C

Model belajar:
    Mana benign
    Mana malware
```

Sedangkan pada Engram:

```text
Training:
    Benign
    Benign
    Benign
    Benign

Model belajar:
    Seperti apa sistem yang normal
```

Model tidak pernah diperlihatkan malware selama proses pembelajaran.

Karena itu pendekatan ini termasuk:

* Unsupervised Anomaly Detection
* One-Class Learning
* Behavioral Detection

---

# Representasi Data

Setiap proses dalam dataset direpresentasikan sebagai sekumpulan fitur numerik.

Contoh sederhana:

```text
Jumlah Process
Jumlah Thread
Jumlah Handle
Jumlah File Handle
Jumlah Registry Key
...
```

Satu proses dapat dianggap sebagai sebuah titik dalam ruang multidimensi.

Misalnya:

```text
Process A
[120, 1500, 20000, 350]

Process B
[125, 1400, 19800, 360]

Process C
[118, 1600, 21000, 340]
```

Karena seluruh data training berasal dari proses benign, titik-titik tersebut akan membentuk kelompok besar yang merepresentasikan kondisi normal sistem.

Secara visual:

```text
        ● ● ●
      ● ● ● ● ●
    ● ● ● ● ● ● ●
      ● ● ● ● ●
        ● ● ●
```

Kelompok inilah yang dipelajari oleh model.

---

# Bagaimana Isolation Forest Belajar?

Isolation Forest tidak mencoba mencari definisi "malware".

Sebaliknya, algoritma mencoba menjawab pertanyaan:

> Seberapa mudah sebuah titik dapat dipisahkan dari titik-titik lainnya?

Untuk melakukan hal tersebut, algoritma membangun banyak pohon keputusan acak (*Isolation Trees*).

Setiap pohon:

1. Memilih fitur secara acak.
2. Memilih nilai pemisah secara acak.
3. Membagi data menjadi kelompok yang lebih kecil.
4. Mengulangi proses hingga titik-titik terisolasi.

---

# Intuisi Utama Isolation Forest

Data normal biasanya:

* jumlahnya banyak
* saling berdekatan
* membentuk cluster padat

Karena itu data normal cenderung sulit dipisahkan.

Sebaliknya data yang aneh:

* jumlahnya sedikit
* berada jauh dari kelompok utama
* lebih mudah dipisahkan

Misalnya:

```text
● ● ● ● ● ● ●
● ● ● ● ● ● ●
● ● ● ● ● ● ●

                X
```

Titik X berada jauh dari kelompok normal.

Akibatnya hanya dibutuhkan sedikit pemisahan untuk mengisolasinya.

---

# Apa yang Dipelajari Model?

Model tidak menyimpan aturan seperti:

```text
Jika thread > 5000
Maka malware
```

Model juga tidak menyimpan tanda tangan malware.

Yang sebenarnya dipelajari adalah struktur statistik dari data normal.

Secara konseptual model memahami:

```text
"Mayoritas proses normal terlihat seperti ini."
```

Ketika sampel baru masuk, model mengukur:

```text
"Seberapa jauh sampel ini dari perilaku normal?"
```

---

# Proses Deteksi Saat Inference

Ketika sebuah proses baru dianalisis:

1. Fitur-fitur proses diekstrak.
2. Fitur tersebut dipetakan ke ruang yang sama dengan data training.
3. Sampel dilewatkan ke seluruh Isolation Tree.
4. Model menghitung seberapa cepat sampel tersebut dapat diisolasi.

Jika sampel cepat terisolasi:

```text
Path Length Pendek
↓
Anomaly Score Tinggi
↓
Mencurigakan
```

Jika sampel sulit diisolasi:

```text
Path Length Panjang
↓
Anomaly Score Rendah
↓
Normal
```

---

# Mengapa Bisa Mendeteksi Malware yang Belum Pernah Dilihat?

Karena model tidak bergantung pada contoh malware.

Model hanya mengetahui:

```text
Inilah bentuk sistem yang sehat.
```

Ketika muncul proses yang memiliki karakteristik berbeda secara signifikan:

```text
Normal Cluster

● ● ● ● ● ●
● ● ● ● ● ●

                    X
```

maka proses tersebut akan dianggap anomali.

Akibatnya model memiliki peluang untuk mendeteksi:

* Malware baru
* Varian malware yang belum dikenal
* Zero-day malware
* Teknik serangan yang belum pernah muncul saat training

---

# Keterbatasan Pendekatan Ini

Kemampuan mendeteksi zero-day bukan berarti semua malware akan terdeteksi.

Jika malware menghasilkan karakteristik yang sangat mirip dengan proses normal:

```text
● ● ● ● ● ●
● ● X ● ● ●
● ● ● ● ● ●
```

maka malware tersebut mungkin terlihat normal bagi model.

Karena itu kualitas fitur sangat menentukan keberhasilan sistem.

Prinsip sederhananya:

```text
Semakin berbeda perilaku malware
dari sistem normal,
semakin mudah dideteksi.
```

---

# Cara Berpikir Engram

Engram bukanlah sistem yang berpikir:

```text
Apakah ini malware?
```

Melainkan:

```text
Apakah ini masih terlihat normal?
```

Jika jawabannya tidak, maka proses tersebut diberi skor kecurigaan yang lebih tinggi.

Dengan kata lain, Engram berfungsi sebagai:

```text
Normal Behavior Detector
```

yang mempelajari pola sistem sehat dan mendeteksi penyimpangan dari pola tersebut.
