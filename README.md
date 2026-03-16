# UNIGE_Advanced_Security

## Installation

### 1. Prérequis système (liboqs C)

**macOS :**
```bash
brew install cmake ninja openssl
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j$(sysctl -n hw.logicalcpu)
sudo cmake --install build
echo 'export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH' >> ~/.zshrc
source ~/.zshrc
```

### 2. Environnement Python
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Vérifier l'installation
```bash
python3 -c "import oqs; print('oqs OK')"
```