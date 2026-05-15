const PAYPAL_API_BASE =
  process.env.PAYPAL_ENV === 'sandbox'
    ? 'https://api-m.sandbox.paypal.com'
    : 'https://api-m.paypal.com'

function requirePayPalEnv() {
  if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
    throw new Error('PayPal is not configured. Add PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET.')
  }
}

async function getPayPalAccessToken() {
  requirePayPalEnv()

  const auth = Buffer.from(
    `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
  ).toString('base64')

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
    throw new Error(
      data.error_description ||
      data.message ||
      'Failed to authenticate with PayPal.'
    )
  }

  return data.access_token
}

export async function createPayPalOrder({
  amount,
  currency,
  description,
  returnUrl,
  cancelUrl,
}) {
  const accessToken = await getPayPalAccessToken()

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({
      intent: 'CAPTURE',
      application_context: {
        brand_name: 'EQY Tweak',
        landing_page: 'LOGIN',
        user_action: 'PAY_NOW',
        return_url: returnUrl,
        cancel_url: cancelUrl,
        shipping_preference: 'NO_SHIPPING',
      },
      purchase_units: [
        {
          description,
          amount: {
            currency_code: currency,
            value: amount,
          },
        },
      ],
    }),
  })

  const data = await res.json().catch(() => ({}))

  console.log('PAYPAL CREATE ORDER RESPONSE:', JSON.stringify(data, null, 2))

  if (!res.ok) {
    throw new Error(
      data.message ||
      data.error_description ||
      'Could not create PayPal order.'
    )
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
      Prefer: 'return=representation',
    },
  })

  const data = await res.json().catch(() => ({}))

  console.log('PAYPAL CAPTURE ORDER RESPONSE:', JSON.stringify(data, null, 2))

  if (!res.ok) {
    throw new Error(
      data.message ||
      data.error_description ||
      'Could not capture PayPal order.'
    )
  }

  return data
}