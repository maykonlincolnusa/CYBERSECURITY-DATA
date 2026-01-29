from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/enrich', methods=['POST'])
def enrich():
    event = request.json
    # adicionar enrichments
    event['enriched'] = True
    return jsonify(event)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)