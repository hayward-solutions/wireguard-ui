-- Add default peer settings to server_config
ALTER TABLE server_config ADD COLUMN default_allowed_ips TEXT DEFAULT '0.0.0.0/0, ::/0';
ALTER TABLE server_config ADD COLUMN default_dns TEXT DEFAULT '';
