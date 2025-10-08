const INVALID_SCOPES = [
	'user:create',
	'user:delete',
	'user_data_storage:create',
	'user_data_storage:delete',
	'roles:create',
	'roles:update',
	'roles:delete',
	'roles:*',
	'audit_logs:create',
	'audit_logs:update',
	'audit_logs:delete',
	'audit_logs:*',
	'oauth_applications:create',
	'oauth_applications:update',
	'oauth_applications:delete',
	'oauth_applications:*',
	'connections:create',
	'connections:update'
];

const SCOPES: Record<string, { icon: string; description: string }> = {
	'user:read': { icon: 'user', description: 'Read your profile data' },
	'user:update': { icon: 'user-pen', description: 'Change your profile data' },
	'user:*': { icon: 'user-cog', description: 'Read and modify your profile' },
	'user_data_storage:read': {
		icon: 'folder-open',
		description: 'Read your additional data storage'
	},
	'user_data_storage:update': {
		icon: 'folder-pen',
		description: 'Modify your additional data storage'
	},
	'user_data_storage:*': {
		icon: 'folder-cog',
		description: 'Full access to additional data in your account'
	},
	'roles:read': { icon: 'crown', description: 'Read your roles' },
	'audit_logs:read': { icon: 'clipboard-list', description: 'Read your audit logs' },
	'oauth_applications:read': { icon: 'code-xml', description: 'Read your OAuth applications' },
	'connections:read': { icon: 'link', description: 'Read your connected OAuth Apps' },
	'connections:delete': { icon: 'unlink', description: 'Disconnect OAuth Apps' },
	'connections:*': { icon: 'link', description: 'Read and disconnect your connected OAuth Apps' }
};

export { SCOPES, INVALID_SCOPES };