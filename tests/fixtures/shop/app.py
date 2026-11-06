from flask import Flask, jsonify, request

from shop.services import orders

app = Flask(__name__)


@app.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    return jsonify(orders.for_customer(customer))
