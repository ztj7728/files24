import os
import time
import uuid
from flask import Flask, request, jsonify, send_from_directory
from threading import Thread

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
EXPIRATION_TIME = 24 * 60 * 60  # 24小时
CUSTOM_DOMAIN = 'https://xxxxx'  # 设置自定义域名
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 用于文件清理的线程
def cleanup_files():
    while True:
        current_time = time.time()
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.getmtime(file_path) + EXPIRATION_TIME < current_time:
                os.remove(file_path)
                print(f"File {filename} has been removed due to expiration.")
        time.sleep(60 * 60)  # 每小时检查一次

# 启动清理线程
cleanup_thread = Thread(target=cleanup_files, daemon=True)
cleanup_thread.start()

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # 获取原始文件扩展名
    file_extension = os.path.splitext(file.filename)[1]
    # 使用 UUID 生成唯一的文件名
    unique_filename = f"{uuid.uuid4()}{file_extension}"

    # 保存文件
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(file_path)

    # 返回自定义域名的文件链接
    file_url = f"{CUSTOM_DOMAIN}/{unique_filename}"
    return jsonify({"file_url": file_url}), 200

@app.route('/<filename>')
def get_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        # 使用 send_from_directory 发送文件
        return send_from_directory(UPLOAD_FOLDER, filename)
    else:
        return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    # 启动Flask服务器，监听所有IP地址并自定义端口
    app.run(debug=True, host='0.0.0.0', port=8080)
