import os
import ctypes
from flask import Flask, request, render_template

app = Flask(__name__)

lib_path = os.path.join(os.path.dirname(__file__), "libscanner.so")
scanner = ctypes.CDLL(lib_path)

scanner.load_signatures.argtypes = [ctypes.c_char_p]
scanner.scan_file_rules.argtypes = [ctypes.c_char_p]
scanner.load_signatures.restype = ctypes.c_int
scanner.scan_file_rules.restype = ctypes.c_int

rules_path = os.path.join(os.path.dirname(__file__), "rules.txt")
scanner.load_signatures(rules_path.encode())

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        file = request.files.get("file")
        if file:
            path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(path)
            threats = scanner.scan_file_rules(path.encode())
            result = f"Ameaças detectadas: {threats}"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
