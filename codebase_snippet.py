# app/integrations/payment_gateway.py

import os
import stripe

stripe.api_key = os.environ["STRIPE_KEY"]

def create_payment_intent(amount_cents, currency, customer_id):
    intent = stripe.PaymentIntent.create(
        amount=amount_cents,
        currency=currency,
        customer=customer_id,
        payment_method_types=["card"],
        capture_method="automatic"
    )
    return intent.id, intent.client_secret

def list_recent_charges(customer_id, limit=10):
    charges = stripe.Charge.list(customer=customer_id, limit=limit)
    return [{"id": c.id, "amount": c.amount, "status": c.status} for c in charges.data]

def create_customer(email, name, metadata=None):
    return stripe.Customer.create(email=email, name=name, metadata=metadata or {})
