import { useTranslation } from 'react-i18next';
import { Form, Input, InputNumber, Select } from 'antd';

export default function OpenvpnFields() {
  const { t } = useTranslation();
  return (
    <>
      <Form.Item
        name={['settings', 'protocol']}
        label={t('pages.inbounds.form.openvpnProtocol', 'Protocol')}
        rules={[{ required: true }]}
      >
        <Select
          options={[
            { value: 'udp', label: 'UDP' },
            { value: 'tcp', label: 'TCP' },
          ]}
        />
      </Form.Item>
      <Form.Item
        name={['settings', 'subnet']}
        label={t('pages.inbounds.form.openvpnSubnet', 'VPN Subnet')}
      >
        <Input placeholder="10.8.0.0" />
      </Form.Item>
      <Form.Item
        name={['settings', 'netmask']}
        label={t('pages.inbounds.form.openvpnNetmask', 'Netmask')}
      >
        <Input placeholder="255.255.255.0" />
      </Form.Item>
      <Form.Item
        name={['settings', 'cipher']}
        label={t('pages.inbounds.form.openvpnCipher', 'Cipher')}
      >
        <Select
          options={[
            { value: 'AES-256-GCM', label: 'AES-256-GCM' },
            { value: 'AES-128-GCM', label: 'AES-128-GCM' },
            { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305' },
          ]}
        />
      </Form.Item>
      <Form.Item
        name={['settings', 'auth']}
        label={t('pages.inbounds.form.openvpnAuth', 'Auth Algorithm')}
      >
        <Select
          options={[
            { value: 'SHA256', label: 'SHA256' },
            { value: 'SHA512', label: 'SHA512' },
            { value: 'SHA1', label: 'SHA1 (legacy)' },
          ]}
        />
      </Form.Item>
      <Form.Item
        name={['settings', 'keepalive']}
        label={t('pages.inbounds.form.openvpnKeepalive', 'Keepalive (seconds)')}
      >
        <InputNumber min={1} max={3600} style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item
        name={['settings', 'maxClients']}
        label={t('pages.inbounds.form.openvpnMaxClients', 'Max Clients')}
      >
        <InputNumber min={1} max={1000} style={{ width: '100%' }} />
      </Form.Item>
    </>
  );
}
