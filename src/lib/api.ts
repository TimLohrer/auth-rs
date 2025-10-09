
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
import User from './models/User';
import type UserUpdates from "./models/UserUpdates";
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async startPasskeyAuth() {
		const startResponse = await fetch(`${this.baseUrl}/auth/passkeys/authenticate/start`);

		if (!startResponse.ok) {
			console.error(await startResponse.json());
			throw new Error(`(${startResponse.status}): ${startResponse.statusText}`);
		}

		const data = await startResponse.json();

		const authenticationId = data.data.authenticationId;
		const publicKey = data.data.challenge.publicKey;

		delete publicKey.userVerification;

		publicKey.challenge = PasskeyUtils.base64URLStringToBuffer(publicKey.challenge);

		const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;

		if (!credential) {
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
						// @ts-expect-error
						authenticatorData: PasskeyUtils.bufferToBase64URLString(
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
			return finishData.data;
		} else {
			console.error(await finishResponse.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
						// @ts-expect-error
						attestationObject: PasskeyUtils.bufferToBase64URLString(
							credential.response.attestationObject
						)
					},
					type: credential.type
				}
			})
		});

		if (finishResponse.ok) {
			const finishData = await finishResponse.json();
			return new Passkey(
				finishData.data.id,
				finishData.data.owner,
				finishData.data.name,
				finishData.data.createdAt
			);
		} else {
			console.error(await finishResponse.json());
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
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}

	async updatePasskey(passkeyId: string, updates: PasskeyUpdates): Promise<Passkey> {
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
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
			return data.data;
		} else {
			console.error(await response.json());
			throw new Error(`(${response.status}): ${response.statusText}`);
		}
	}
}

export default AuthRsApi;