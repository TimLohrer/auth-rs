
import AuthStateManager from "./auth";
import type { AuditLog } from "./models/AuditLog";
import type OAuthApplication from "./models/OAuthApplication";
import type OAuthApplicationUpdates from "./models/OAuthApplicationUpdates";
import type OAuthConnection from "./models/OAuthConnection";
import Passkey from "./models/Passkey";
import type PasskeyUpdates from "./models/PasskeyUpdates";
import type RegistrationToken from "./models/RegistrationToken";
import type RegistrationTokenUpdates from "./models/RegistrationTokenUpdates";
import type Role from "./models/Role";
import type RoleUpdates from "./models/RoleUpdates";
import type Settings from "./models/Settings";
import type SettingsUpdates from "./models/SettingsUpdates";
import { Toast } from './models/Toast';
import User from './models/User';
import type UserUpdates from './models/UserUpdates';
import { showToast } from './store/toastStore';
import PasskeyUtils from './utils/passkeyUtils';

class AuthRsApi {
	private baseUrl: string;
	private token: string | null = null;
	private currentMfaFlowId: string | null = null;

	constructor(url: string) {
		console.info('Base URL:', url);
		this.baseUrl = url;
	}

	setToken(token: string | null) {
		this.token = token;
	}

	async checkOnlineState(): Promise<string | null> {
		const response = await fetch(this.baseUrl);

		const data = await response.json();

		if (response.ok) {
			return data.data.version;
		} else {
			showToast(new Toast('Backend not reachable!', 'error', 10000));
			return null;
		}
	}

	async getSettings(): Promise<Settings> {
		const response = await fetch(`${this.baseUrl}/settings`, {
			method: 'GET'
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load settings!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updateSettings(updates: SettingsUpdates): Promise<Settings> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/admin/settings`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Settings updated successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update settings!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async login(email: string, password: string) {
		const response = await fetch(`${this.baseUrl}/auth/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ email, password })
		});

		if (response.ok) {
			const data = await response.json();
			if (data.data?.mfaRequired) {
				this.currentMfaFlowId = data.data.mfaFlowId;

				return data.data;
			}
			new AuthStateManager(this.baseUrl).setToken(data.data.token);
			this.token = data.data.token;
			showToast(new Toast('Login successful!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Incorrect email or password!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async mfa(code: string) {
		if (!this.currentMfaFlowId) {
			throw new Error('No MFA flow ID');
		}

		const response = await fetch(`${this.baseUrl}/auth/mfa`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ code, flowId: this.currentMfaFlowId })
		});

		if (response.ok) {
			const data = await response.json();
			new AuthStateManager(this.baseUrl).setToken(data.data.token);
			this.token = data.data.token;
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Incorrect MFA code!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async startPasskeyAuth() {
		const startResponse = await fetch(`${this.baseUrl}/auth/passkeys/authenticate/start`);

		if (!startResponse.ok) {
			console.error(await startResponse.json());
			showToast(new Toast('Failed to start passkey authentication!', 'error'));
			throw new Error(`(${startResponse.status}): ${startResponse.statusText}`);
		}

		const data = await startResponse.json();

		const authenticationId = data.data.authenticationId;
		const publicKey = data.data.challenge.publicKey;

		delete publicKey.userVerification;

		publicKey.challenge = PasskeyUtils.base64URLStringToBuffer(publicKey.challenge);

		const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;

		if (!credential) {
			showToast(new Toast('Passkey authentication failed!', 'error'));
			throw new Error('No credential created!');
		}

		const finishResponse = await fetch(`${this.baseUrl}/auth/passkeys/authenticate/finish`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				authenticationId: authenticationId,
				credential: {
					id: credential.id,
					rawId: PasskeyUtils.bufferToBase64URLString(credential.rawId),
					response: {
						authenticatorData: PasskeyUtils.bufferToBase64URLString(
							// @ts-expect-error
							credential.response.authenticatorData
						),
						clientDataJSON: PasskeyUtils.bufferToBase64URLString(
							credential.response.clientDataJSON
						),
						// @ts-expect-error
						signature: PasskeyUtils.bufferToBase64URLString(credential.response.signature),
						// @ts-expect-error
						userHandle: PasskeyUtils.bufferToBase64URLString(credential.response.userHandle)
					},
					extentions: credential.getClientExtensionResults(),
					type: credential.type
				}
			})
		});

		if (finishResponse.ok) {
			const finishData = await finishResponse.json();
			new AuthStateManager(this.baseUrl).setToken(finishData.data.token);
			this.token = finishData.data.token;
			showToast(new Toast('Login successful!', 'success'));
			return finishData.data;
		} else {
			console.error(await finishResponse.json());
			showToast(new Toast('Failed to finish passkey authentication!', 'error'));
			throw new Error(`(${finishResponse.status}): ${finishResponse.statusText}`);
		}
	}

	async enableMfa(user: User, password: string) {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${user._id}/mfa/totp/enable`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({ password })
		});

		if (response.ok) {
			const data = await response.json();
			if (data.data?.mfaRequired) {
				this.currentMfaFlowId = data.data.mfaFlowId;
			}
			showToast(new Toast('MFA enabled successfully!', 'success', 10000));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to enable MFA!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async disableMfa(user: User, code: string): Promise<User> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${user._id}/mfa/totp/disable`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({ code })
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('MFA disabled successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to disable MFA! Incorrect code?', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async disableMfaForUser(user: User, targetUserId: string): Promise<User> {
		if (!this.token) {
			throw new Error('No token');
		}

		if (!User.isSystemAdmin(user)) {
			throw new Error('Only system admins can disable MFA for other users.');
		}

		const response = await fetch(`${this.baseUrl}/users/${targetUserId}/mfa/totp/disable`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({ code: null })
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Successfully disabled MFA for user!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to disable MFA for user!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async createUser(
		email: string,
		password: string,
		firstName: string,
		lastName: string,
		registrationCode: string | null
	): Promise<User> {
		const response = await fetch(`${this.baseUrl}/users`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({
				email,
				password,
				firstName,
				lastName: lastName.length > 0 ? lastName : null,
				registrationCode
			})
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('User created successfully!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to create user!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getCurrentUser(): Promise<User> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/@me`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load current user!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getAllUsers(): Promise<User[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load users!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async registerPasskey(type: string = 'virtual'): Promise<Passkey> {
		if (!this.token) {
			throw new Error('No token');
		}

		const startResponse = await fetch(`${this.baseUrl}/passkeys/register/start?type=${type}`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (!startResponse.ok) {
			console.error(await startResponse.json());
			showToast(new Toast('Failed to start passkey registration!', 'error'));
			throw new Error(`(${startResponse.status}): ${startResponse.statusText}`);
		}

		const data = await startResponse.json();

		const registrationId = data.data.registrationId;
		const publicKey = data.data.challenge.publicKey;

		// The next line makes the registration of physical keys work!
		delete publicKey.authenticatorSelection.authenticatorAttachment;
		publicKey.user.id = PasskeyUtils.base64URLStringToBuffer(publicKey.user.id);
		publicKey.challenge = PasskeyUtils.base64URLStringToBuffer(publicKey.challenge);
		publicKey.excludeCredentials = publicKey.excludeCredentials.map((credential: any) => {
			credential.id = PasskeyUtils.base64URLStringToBuffer(credential.id);
			return credential;
		});

		const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;

		if (!credential) {
			showToast(new Toast('Passkey registration failed!', 'error'));
			throw new Error('No credential created!');
		}

		const finishResponse = await fetch(`${this.baseUrl}/passkeys/register/finish`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({
				registrationId: registrationId,
				credential: {
					id: credential.id,
					rawId: PasskeyUtils.bufferToBase64URLString(credential.rawId),
					response: {
						clientDataJSON: PasskeyUtils.bufferToBase64URLString(
							credential.response.clientDataJSON
						),
						attestationObject: PasskeyUtils.bufferToBase64URLString(
							// @ts-expect-error
							credential.response.attestationObject
						)
					},
					type: credential.type
				}
			})
		});

		if (finishResponse.ok) {
			const finishData = await finishResponse.json();
			showToast(new Toast('Passkey registered successfully!', 'success'));
			return new Passkey(
				finishData.data.id,
				finishData.data.owner,
				finishData.data.name,
				finishData.data.createdAt
			);
		} else {
			console.error(await finishResponse.json());
			showToast(new Toast('Failed to finish passkey registration!', 'error'));
			throw new Error(`(${finishResponse.status}): ${finishResponse.statusText}`);
		}
	}

	async getUserPasskeys(userId: string): Promise<Passkey[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${userId}/passkeys`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load passkeys!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getAllPasskeys(): Promise<Passkey[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/passkeys`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load passkeys!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updatePasskey(
		passkeyId: string,
		updates: PasskeyUpdates,
		supressSuccessToast: boolean = false
	): Promise<Passkey> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/passkeys/${passkeyId}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			if (!supressSuccessToast) {
				showToast(new Toast('Passkey updated successfully!', 'info'));
			}
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update passkey!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async deletePasskey(passkeyId: string): Promise<null> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/passkeys/${passkeyId}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Passkey deleted successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to delete passkey!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updateUser(user: User, updates: UserUpdates): Promise<User> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${user._id}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('User updated successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update user!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async deleteUser(user: User): Promise<User> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${user._id}`, {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('User deleted successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to delete user!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async createRole(name: string): Promise<Role> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/roles`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({ name })
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Role created successfully!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to create role!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getAllRoles(): Promise<Role[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/roles`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load roles!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getRole(roleId: string): Promise<Role> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/roles/${roleId}`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load role!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updateRole(role: Role, updates: RoleUpdates): Promise<Role> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/roles/${role._id}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Role updated successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update role!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async deleteRole(role: Role): Promise<Role> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/roles/${role._id}`, {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Role deleted successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to delete role!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getConnections(user: User): Promise<OAuthConnection[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users/${user._id}/connections`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load connections!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async disconnectConnection(connection: OAuthConnection): Promise<null> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/connections/${connection.application._id}`, {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Connection unlinked successfully!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to unlink connection!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async createOAuthApplication(
		name: string,
		description: string | null,
		redirectUris: string[]
	): Promise<OAuthApplication> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth-applications`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({
				name,
				description,
				redirectUris
			})
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('OAuth application created successfully!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to create OAuth application!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getOAuthApplication(clientId: string): Promise<OAuthApplication> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth-applications/${clientId}`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load OAuth application!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getOAuthApplications(): Promise<OAuthApplication[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth-applications`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load OAuth applications!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async authorizeOAuthApplication(clientId: string, redirectUri: string, scope: string[]) {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth/authorize`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({
				clientId,
				redirectUri,
				scope
			})
		});

		if (response.ok) {
			const data = await response.json();
			return data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to authorize application!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updateOAuthApplication(
		application: OAuthApplication,
		updates: OAuthApplicationUpdates
	): Promise<OAuthApplication> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth-applications/${application._id}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('OAuth application updated successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update OAuth application!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async deleteOAuthApplication(application: OAuthApplication): Promise<OAuthApplication> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/oauth-applications/${application._id}`, {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('OAuth application deleted successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to delete OAuth application!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getAuditLogs(user: User | null): Promise<AuditLog[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		let url: string;
		if (user) {
			url = `${this.baseUrl}/users/${user._id}/audit-logs`;
		} else {
			url = `${this.baseUrl}/audit-logs`;
		}

		const response = await fetch(url, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load audit logs!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getUsers(): Promise<User[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/users`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load users!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async createRegistrationToken(
		maxUses: number,
		expiresIn: number | null
	): Promise<RegistrationToken> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/registration-tokens`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify({ maxUses, expiresIn })
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Registration token created successfully!', 'success'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to create registration token!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getRegistrationToken(tokenId: string): Promise<RegistrationToken> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/registration-tokens/${tokenId}`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load registration token!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async getAllRegistrationTokens(): Promise<RegistrationToken[]> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/registration-tokens`, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to load registration tokens!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updateRegistrationToken(
		token: RegistrationToken,
		updates: RegistrationTokenUpdates
	): Promise<RegistrationToken> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/registration-tokens/${token._id}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			},
			body: JSON.stringify(updates)
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Registration token updated successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to update registration token!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async deleteRegistrationToken(token: RegistrationToken): Promise<RegistrationToken> {
		if (!this.token) {
			throw new Error('No token');
		}

		const response = await fetch(`${this.baseUrl}/registration-tokens/${token._id}`, {
			method: 'DELETE',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.token}`
			}
		});

		if (response.ok) {
			const data = await response.json();
			showToast(new Toast('Registration token deleted successfully!', 'info'));
			return data.data;
		} else {
			console.error(await response.json());
			showToast(new Toast('Failed to delete registration token!', 'error'));
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}
}

export default AuthRsApi;