# Isolation Forest 

Isolation Forest adalah algoritma dalam Machine Learning yang dipakai untuk mendeteksi anomaly yaitu data yang berbeda jauh dari mayoritas data lainnya

# Model dikasih contoh "Komputer Sehat"
saya menggunakan dataset memory proses windows MalMem Canadian Institute for Cybersecurity (CIC) pada tahun 2022, dataset berisi 58.596 sampel, yang dibagi rata menjadi 
29.298 sampel benign (aktivitas normal pengguna, seperti membuka browser, mengetik, dll) dan 29.298 sampel malware (sistem yang telah dieksekusi malware).

saat training, semua sampel malware dibuang, jadi, model hanya melihat dunia yang dianggap normal
