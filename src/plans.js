export const plans = {
  standard_7d: {
    name: '7 Days Standard',
    price: 5,
    days: 7,
    premium: false,
    features: ['Core tweaks', 'Game presets', 'Protected download'],
  },
  standard_30d: {
    name: '30 Days Standard',
    price: 12,
    days: 30,
    premium: false,
    features: ['All standard tweaks', 'Download access', 'Support ticket'],
  },
  standard_60d: {
    name: '60 Days Standard',
    price: 19,
    days: 60,
    premium: false,
    features: ['HWID lock', 'Restore prompts', 'Update checks'],
  },
  standard_90d: {
    name: '90 Days Standard',
    price: 24,
    days: 90,
    premium: false,
    features: ['Long access', 'Priority queue', 'Device lock'],
  },
  standard_lifetime: {
    name: 'Lifetime Standard',
    price: 45,
    days: null,
    premium: false,
    features: ['Lifetime standard', 'Future standard updates', 'Discord support'],
  },
  premium_14d: {
    name: '14 Days Premium',
    price: 8,
    days: 14,
    premium: true,
    features: ['Premium tweaks', 'Advanced latency presets', 'Protected download'],
  },
  premium_30d: {
    name: '30 Days Premium',
    price: 14,
    days: 30,
    premium: true,
    features: ['Premium optimization layer', 'Priority support', 'Premium updates'],
  },
  premium_lifetime: {
    name: 'Lifetime Premium',
    price: 50,
    days: null,
    premium: true,
    features: ['Lifetime premium', 'Elite tweak modules', 'Future premium updates'],
  },
}

export const publicPlans = Object.entries(plans).map(([id, plan]) => ({
  id,
  name: plan.name,
  price: plan.price,
  days: plan.days,
  premium: plan.premium,
  features: plan.features,
}))
