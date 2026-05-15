const PAYPAL_API_BASE = process.env.PAYPAL_ENV === 'sandbox'
  ? 'https://api-m.sandbox.paypal.com'
  : 'https://api-m.paypal.com'

async function getPayPalAccessToken() {
  if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
    throw new Error('PayPal environment variables are missing.')
  }

  const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64')

  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    console.error('PayPal auth error:', data)
    throw new Error(data.error_description || data.message || 'Failed to authenticate with PayPal.')
  }

  return data.access_token
}

export async function createPayPalOrder({ amount, currency, description, returnUrl, cancelUrl }) {
  const accessToken = await getPayPalAccessToken()

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [{
        description,
        amount: { currency_code: currency, value: amount },
      }],
      application_context: {
        brand_name: 'EQY Tweak',
        landing_page: 'LOGIN',
        shipping_preference: 'NO_SHIPPING',
        user_action: 'PAY_NOW',
        return_url: returnUrl,
        cancel_url: cancelUrl,
      },
    }),
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    console.error('PayPal create order error:', data)
    throw new Error(data.message || data.error_description || 'Could not create PayPal order.')
  }

  return data
}

export async function capturePayPalOrder(orderId) {
  const accessToken = await getPayPalAccessToken()

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    console.error('PayPal capture error:', data)
    throw new Error(data.message || data.error_description || 'Could not capture PayPal order.')
  }

  return data
}
