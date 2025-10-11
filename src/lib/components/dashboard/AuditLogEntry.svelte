<script lang="ts">
    import { LogIn, MinusCircle, Pencil, PlusCircle, ShieldCheck, ShieldX, KeyRound } from 'lucide-svelte';
	import DateUtils from "$lib/utils/dateUtils";
	import { AuditLog, AuditLogAction, AuditLogEntityType } from "$lib/models/AuditLog";
	import type OAuthApplication from "$lib/models/OAuthApplication";
	import type RegistrationToken from '$lib/models/RegistrationToken';
	import type Role from "$lib/models/Role";
	import User from "$lib/models/User";
	import type Passkey from '$lib/models/Passkey';
	import { jsonAction } from '$lib/utils/jsonAttributes';

    export let user: User;
    export let auditLog: AuditLog;
    export let users: User[];
    export let roles: Role[];
    export let applications: OAuthApplication[];
    export let registrationTokens: RegistrationToken[];
    export let passkeys: Passkey[];

    $: isOpen = false;

    function getEntityName(entityType: AuditLogEntityType, entityId: string): string {
        if (entityType == AuditLogEntityType.User) {
            if (entityId == user._id && entityId !== User.DEFAULT_USER_ID) {
                return "You";
            } else if (users.find(u => u._id == entityId) != null) {;
                const u = users.find(u => u._id == entityId)!;
                return `${u.firstName}${user.lastName.length > 0 ? ' ' : ''}${u.lastName}`;
            } else {
                return entityId;
            }
        } else if (entityType == AuditLogEntityType.Role) {
            return roles.find(r => r._id == entityId)?.name ?? entityId;
        } else if (entityType == AuditLogEntityType.OAuthApplication) {
            return applications.find(a => a._id == entityId)?.name ?? entityId;
        } else if (entityType == AuditLogEntityType.RegistrationToken) {
            return registrationTokens.find(t => t._id == entityId)?.code ?? entityId;
        } else if (entityType == AuditLogEntityType.Passkey) {
            return passkeys.find(p => p.id == entityId)?.name ?? entityId;
        } else if (entityType == AuditLogEntityType.Settings) {
            return "SETTINGS";
        } else {
            return "Unknown";
        }
    }

    function getAuditLogString(log: AuditLog): string {
        const author = getEntityName(AuditLogEntityType.User, log.authorId);
        const target = getEntityName(log.entityType, log.entityId);
        const action = log.action.toLowerCase() + 'd';

        if (auditLog.reason.toUpperCase().includes('ENABLE TOTP')) {
            return `${target} enabled 2FA.`;
        } else if (auditLog.reason.toUpperCase().includes('DISABLE TOTP')) {
            if (log.authorId !== log.entityId) {
                return `${author} disabled 2FA for ${target}.`;
            }
            return `${target} disabled 2FA.`;
        } else if (auditLog.reason.toUpperCase().includes("PASSKEY LOGIN SUCCESSFUL")) {
            const passkeyId = auditLog.reason.split('|')[1];
            return `${author} logged ${target.toUpperCase() == 'YOU' ? 'in' : `into ${target}\'s account`} using the passkey <span class="text-[14px] opacity-75">${getEntityName(AuditLogEntityType.Passkey, passkeyId)}</span>.`;
        } else if (auditLog.reason.toUpperCase().includes("LOGIN SUCCESSFUL")) {
            return `New ${auditLog.reason.toUpperCase().includes('MFA') ? '2FA ': ''}login on ${target.toUpperCase() == 'YOU' ? 'your' : `${target}\'s`} account.`;
        } if (auditLog.entityType == AuditLogEntityType.User && auditLog.action == AuditLogAction.Create && auditLog.reason.split('|').length >= 3 && auditLog.reason.split('|')[1].toUpperCase() == 'REGISTRATION_TOKEN') {
            const tokenId = auditLog.reason.split('|')[2];
            return `${target} ${action} ${target.toUpperCase() == 'YOU' ? 'your' : 'their'} profile using the registration code <span class="text-[14px] opacity-75">${getEntityName(AuditLogEntityType.RegistrationToken, tokenId)}</span>.`;
        } else if (auditLog.entityType == AuditLogEntityType.Passkey) {
            return `${author} ${auditLog.action == AuditLogAction.Create ? 'registered' : auditLog.action == AuditLogAction.Update ? 'updated ' : 'deleted'} the passkey <span class="text-[14px] opacity-75">${getEntityName(AuditLogEntityType.Passkey, auditLog.entityId)}</span>`;
        } else if (target.toUpperCase() == 'YOU') {
            return `${author} ${action} your profile.`;
        } else if (target == 'SETTINGS') {
            return `${author} ${action} the settings.`;
        } else {
            return `${author} ${action} the ${log.entityType == AuditLogEntityType.OAuthApplication ? 'OAuth Application' : log.entityType == AuditLogEntityType.RegistrationToken ? 'Registration Token' : log.entityType.toLowerCase()} <span class="text-[14px] opacity-75">${target}</span>`;
        }
    }

    function getChangeLogString(key: string, oldValue: string, newValue: string): string {
        let result: string;
        let color: string;
        const getContainer = () => `<p class="opacity-80 text-${color}-600">{{VALUE}}</p>`;

        if (key == 'roles' || key == 'auto_roles') {
            let oldRoles = oldValue.split(',');
            let newRoles = newValue.split(',');

            if (oldRoles[0] == '') {
                oldRoles = [];
            }
            if (newRoles[0] == '') {
                newRoles = [];
            }
            
            let action = oldRoles.length > newRoles.length ? 'Removed' : 'Added';
            let roleId: string;

            if (action.toUpperCase() == 'REMOVED') {
                roleId = oldRoles.filter(r => !newRoles.includes(r))[0];
            } else {
                roleId = newRoles.filter(r => !oldRoles.includes(r))[0];
            }

            color = action.toUpperCase() == 'ADDED' ? 'green' : 'red';
            result = `${action} role <i>${getEntityName(AuditLogEntityType.Role, roleId)}</i>`;
        } else if (key == 'redirect_uris') {
            const oldURIs = oldValue.split(',');
            const newURIs = newValue.split(',');
            
            let action = oldURIs.length > newURIs.length ? 'Removed' : 'Added';
            let uris: string[];
            
            if (action.toUpperCase() == 'REMOVED') {
                uris = oldURIs.filter(uri => !newURIs.includes(uri));
            } else {
                uris = newURIs.filter(uri => !oldURIs.includes(uri));
            }

            color = action.toUpperCase() == 'ADDED' ? 'green' : 'red';
            result = `${action} redirect URI${uris.length > 1 ? '\'s' : ''} <i>${uris.join(', ')}</i>`;
        } else if (key == 'password') {
            color = 'yellow';
            result = `Changed password`;
        } else {
            color = 'yellow';
            result = `${AuditLog.auditLogChangeLogKeys[key] ?? key.replaceAll('_', ' ')}: <i>${oldValue}</i> -> <i>${newValue}</i>`;
        }

        // Don't  question this, is doesnt work the 'normal' way ok?
        return getContainer().replace('{{VALUE}}', result);
    }

    function isAuditLogExpandable(log: AuditLog): boolean {
        return log.oldValues && log.newValues && !log.reason.toUpperCase().includes('TOTP');
    }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div
    class="flex flex-col items-start border-[1px] border-[#333] rounded-md {isAuditLogExpandable(auditLog) ? 'cursor-pointer' : ''}"
    style="padding: 15px;"
    on:click={isAuditLogExpandable(auditLog) ? () => isOpen = !isOpen : () => {}}
    use:jsonAction={{ data: auditLog, title: "Audit Log Data" }}
>
    <div class="flex flex-row justify-between w-full">
        <div class="flex flex-row gap-[15px]">
            {#if auditLog.reason.toUpperCase().includes("LOGIN SUCCESSFUL")}
                <LogIn height="30" width="30" class="text-blue-500" />
            {:else if auditLog.reason.toUpperCase().includes('ENABLE TOTP')}
                <ShieldCheck height="30" width="30" class="text-green-500" />
            {:else if auditLog.reason.toUpperCase().includes('DISABLE TOTP')}
                <ShieldX height="30" width="30" class="text-red-500" />
            {:else if auditLog.entityType == AuditLogEntityType.Passkey && auditLog.action == AuditLogAction.Create}
                <KeyRound height="30" width="30" class="text-green-500" />
            {:else if auditLog.entityType == AuditLogEntityType.Passkey && auditLog.action == AuditLogAction.Delete}
                <KeyRound height="30" width="30" class="text-red-500" />
            {:else if auditLog.reason.toUpperCase().includes('CREATE')}
                <PlusCircle height="30" width="30" class="text-green-500" />
            {:else if auditLog.reason.toUpperCase().includes('DELETE')}
                <MinusCircle height="30" width="30" class="text-red-500" />
            {:else}
                <Pencil height="30" width="30" class="text-yellow-400" />
            {/if}
            <p class="text-[16px]">{@html getAuditLogString(auditLog)}</p>
        </div>
        <p class="text-[16px] opacity-35 text-nowrap">{DateUtils.getFullDateString(AuditLog.getCreatedAt(auditLog))}</p>
    </div>
    {#if isOpen}
        <div style="margin-top: 10px; padding: 5px;">
            {#each Object.keys(auditLog.oldValues) as oldValueKey, i}
                <div class="flex flex-row gap-[10px]">
                    <p>{Object.keys(auditLog.oldValues).length < 2 ? '-> ' : `${i + 1}.`}</p>
                    <p>{@html getChangeLogString(oldValueKey, auditLog.oldValues[oldValueKey] ?? '', auditLog.newValues[oldValueKey] ?? '')}</p>
                </div>
            {/each}
        </div>
    {/if}
</div>