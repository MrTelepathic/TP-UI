import { z } from 'zod';

// OpenVPN client — each client authenticates with a username+password pair.
// The panel generates client certificates and .ovpn config files.
export const OpenvpnClientSchema = z.object({
  password: z.string().min(1),
  email: z.string().min(1),
  limitIp: z.number().int().min(0).default(0),
  totalGB: z.number().int().min(0).default(0),
  expiryTime: z.number().int().default(0),
  enable: z.boolean().default(true),
  tgId: z.union([z.number(), z.string()]).transform((v) => Number(v) || 0).default(0),
  subId: z.string().default(''),
  comment: z.string().default(''),
  reset: z.number().int().min(0).default(0),
  created_at: z.number().int().optional(),
  updated_at: z.number().int().optional(),
});
export type OpenvpnClient = z.infer<typeof OpenvpnClientSchema>;

export const OpenvpnInboundSettingsSchema = z.object({
  protocol: z.enum(['udp', 'tcp']).default('udp'),
  subnet: z.string().default('10.8.0.0'),
  netmask: z.string().default('255.255.255.0'),
  cipher: z.string().default('AES-256-GCM'),
  auth: z.string().default('SHA256'),
  keepalive: z.number().int().min(1).default(10),
  maxClients: z.number().int().min(1).default(100),
  dns: z.array(z.string()).default(['8.8.8.8', '8.8.4.4']),
  clients: z.array(OpenvpnClientSchema).default([]),
});
export type OpenvpnInboundSettings = z.infer<typeof OpenvpnInboundSettingsSchema>;
