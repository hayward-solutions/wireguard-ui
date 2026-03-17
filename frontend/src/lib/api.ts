interface APIResponse<T> {
	data: T | null;
	error: { code: string; message: string } | null;
}

class APIClient {
	private baseURL: string;

	constructor(baseURL = '') {
		this.baseURL = baseURL;
	}

	private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
		const opts: RequestInit = {
			method,
			headers: { 'Content-Type': 'application/json' },
			credentials: 'include'
		};

		if (body) {
			opts.body = JSON.stringify(body);
		}

		const res = await fetch(`${this.baseURL}${path}`, opts);

		if (res.status === 401) {
			window.location.href = '/login';
			throw new Error('Unauthorized');
		}

		const json: APIResponse<T> = await res.json();

		if (json.error) {
			throw new Error(json.error.message);
		}

		return json.data as T;
	}

	// Auth
	async me() {
		return this.request<{ id: string; email: string; name: string; role: string }>('GET', '/auth/me');
	}

	async logout() {
		return this.request<void>('POST', '/auth/logout');
	}

	// Server
	async getServer() {
		return this.request<ServerConfig>('GET', '/api/v1/server');
	}

	async updateServer(data: Partial<ServerConfig>) {
		return this.request<ServerConfig>('PUT', '/api/v1/server', data);
	}

	async applyServer() {
		return this.request<{ message: string }>('POST', '/api/v1/server/apply');
	}

	// Peers
	async listPeers() {
		return this.request<Peer[]>('GET', '/api/v1/peers');
	}

	async getPeer(id: string) {
		return this.request<Peer>('GET', `/api/v1/peers/${id}`);
	}

	async createPeer(data: { name: string; allowed_ips?: string; dns?: string }) {
		return this.request<Peer>('POST', '/api/v1/peers', data);
	}

	async updatePeer(id: string, data: Partial<Peer>) {
		return this.request<Peer>('PUT', `/api/v1/peers/${id}`, data);
	}

	async deletePeer(id: string) {
		return this.request<void>('DELETE', `/api/v1/peers/${id}`);
	}

	async togglePeer(id: string) {
		return this.request<Peer>('PATCH', `/api/v1/peers/${id}/toggle`);
	}

	getConfigURL(id: string) {
		return `/api/v1/peers/${id}/config`;
	}

	getQRCodeURL(id: string) {
		return `/api/v1/peers/${id}/qrcode`;
	}

	// Stats
	async getStats() {
		return this.request<PeerStats[]>('GET', '/api/v1/stats');
	}

	// Users
	async listUsers() {
		return this.request<User[]>('GET', '/api/v1/users');
	}

	async getUser(id: string) {
		return this.request<User>('GET', `/api/v1/users/${id}`);
	}

	async createUser(data: { username: string; password: string; name?: string; role?: string }) {
		return this.request<User>('POST', '/api/v1/users', data);
	}

	async updateUser(id: string, data: { username?: string; name?: string; role?: string }) {
		return this.request<User>('PUT', `/api/v1/users/${id}`, data);
	}

	async deleteUser(id: string) {
		return this.request<void>('DELETE', `/api/v1/users/${id}`);
	}

	async resetPassword(id: string, password: string) {
		return this.request<{ message: string }>('POST', `/api/v1/users/${id}/reset-password`, { password });
	}

	async changePassword(currentPassword: string, newPassword: string) {
		return this.request<{ message: string }>('POST', '/api/v1/me/password', {
			current_password: currentPassword,
			new_password: newPassword
		});
	}

	// API Tokens
	async listTokens() {
		return this.request<APIToken[]>('GET', '/api/v1/me/tokens');
	}

	async createToken(name: string) {
		return this.request<APITokenCreateResponse>('POST', '/api/v1/me/tokens', { name });
	}

	async deleteToken(id: string) {
		return this.request<void>('DELETE', `/api/v1/me/tokens/${id}`);
	}
}

export interface ServerConfig {
	id: string;
	public_key: string;
	listen_port: number;
	address: string;
	dns: string;
	mtu: number;
	post_up: string;
	post_down: string;
	endpoint: string;
	default_allowed_ips: string;
	default_dns: string;
}

export interface Peer {
	id: string;
	name: string;
	public_key: string;
	allowed_ips: string;
	address: string;
	dns: string;
	persistent_keepalive: number;
	enabled: boolean;
	created_by: string;
	created_by_name?: string;
	created_at: string;
	updated_at: string;
}

export interface User {
	id: string;
	username: string;
	name: string;
	role: string;
	created_at: string;
}

export interface APIToken {
	id: string;
	user_id: string;
	name: string;
	token_prefix: string;
	last_used: string | null;
	expires_at: string | null;
	created_at: string;
}

export interface APITokenCreateResponse {
	id: string;
	name: string;
	token: string;
	token_prefix: string;
	created_at: string;
}

export interface PeerStats {
	public_key: string;
	endpoint: string;
	last_handshake: string;
	transfer_rx: number;
	transfer_tx: number;
	connected: boolean;
}

export const api = new APIClient();
