import { goto } from "$app/navigation";
import AuthRsApi from "./api";
import type User from "./models/User";

class AuthStateManager {
	private apiUrl: string;
	constructor(apiUrl: string) {
		this.apiUrl = apiUrl;
	}

	getToken() {
		return localStorage.getItem('token');
	}

	setToken(token: string) {
		localStorage.setItem('token', token);
	}

	clearToken() {
		localStorage.removeItem('token');
	}

	getActiveUserId(): string | null {
		if (this.getToken()) {
			const payload = this.getToken()!.split('.')[1];
			const decoded = JSON.parse(atob(payload));
			return decoded.sub || null;
		}
		return null;
	}

	getActiveDeviceId(): string | null {
		if (this.getToken()) {
			const payload = this.getToken()!.split('.')[1];
			const decoded = JSON.parse(atob(payload));
			return decoded.data.deviceId || null;
		}
		return null;
	}

	async handlePageLoad(params: string[] | null = null): Promise<[AuthRsApi, User] | null> {
		const token = this.getToken();
		if (token) {
			const api = new AuthRsApi(this.apiUrl);
			api.setToken(token);
			try {
				const user = await api.getCurrentUser();
				return [api, user];
			} catch {
				this.clearToken();
				goto(`/login${params ? `?${params.join('&')}` : ''}`);
				return null;
			}
		} else {
			goto(`/login${params ? `?${params.join('&')}` : ''}`);
			return null;
		}
	}

	logout() {
		this.clearToken();
		goto(`/logout`);
	}
}

export default AuthStateManager;