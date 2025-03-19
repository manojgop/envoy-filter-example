from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    data = request.json
    return jsonify({"message": "POST request received"}), 200
    #return jsonify({"message": "POST request received", "data": data}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
