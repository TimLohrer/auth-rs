class AuditLog {
	public id: string;
	public entityId: string;
	public entityType: AuditLogEntityType;
	public action: AuditLogAction;
	public reason: string;
	public authorId: string;
	public oldValues: Record<string, string>;
	public newValues: Record<string, string>;
	public createdAt: number;

	constructor(
		id: string,
		entityId: string,
		entityType: AuditLogEntityType,
		action: AuditLogAction,
		reason: string,
		authorId: string,
		oldValues: Record<string, string>,
		newValues: Record<string, string>,
		createdAt: number
	) {
		this.id = id;
		this.entityId = entityId;
		this.entityType = entityType;
		this.action = action;
		this.reason = reason;
		this.authorId = authorId;
		this.oldValues = oldValues;
		this.newValues = newValues;
		this.createdAt = createdAt;
	}

	static auditLogChangeLogKeys: Record<string, string> = {
		// User
		email: 'Email',
		first_name: 'First Name',
		last_name: 'Last Name',
		password: 'Password',
		totp_secret: 'TOTP Secret',
		disabled: 'Disabled',

		// Role
		name: 'Name',

		// OAuthApplication
		// "name": "Name", -> Duplicate key
		description: 'Description',
		redirect_uris: 'Redirect URIs',

		// RegistrationToken
		max_uses: 'Max Uses',
		expires_in: 'Expires At',
		auto_roles: 'Auto Roles',

		// Settings
		open_registration: 'Open Registrations',
		allow_oauth_apps_for_users: 'Allow OAuth Apps for Users'
	};

	static getCreatedAt(auditLog: AuditLog): Date {
		return new Date(auditLog.createdAt);
	}
}

enum AuditLogAction {
    Create = 'Create',
    Update = 'Update',
    Login = 'Login',
    Delete = 'Delete',
}

enum AuditLogEntityType {
    User = 'User',
    Role = 'Role',
    OAuthApplication = 'OAuthApplication',
    RegistrationToken = 'RegistrationToken',
    Passkey = 'Passkey',
    Settings = 'Settings',
    Unknown = 'Unknown',
}

export { AuditLog, AuditLogAction, AuditLogEntityType };