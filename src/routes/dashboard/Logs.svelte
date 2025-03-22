<script lang="ts">
	import type AuthRsApi from "$lib/api";
	import { AuditLog, AuditLogAction, AuditLogEntityType } from "$lib/models/AuditLog";
	import type OAuthApplication from "$lib/models/OAuthApplication";
	import type Role from "$lib/models/Role";
	import UserMinimal from "$lib/models/User";
	import { onMount } from "svelte";

    export let api: AuthRsApi;
    export let user: UserMinimal;
    export let users: UserMinimal[];
    export let roles: Role[];
    export let applications: OAuthApplication[];
    export let auditLogs: AuditLog[];

    function getEntityName(entityType: AuditLogEntityType, entityId: string): string {
        if (entityType == AuditLogEntityType.User) {
            if (entityId == user._id) {
                return "You";
            } else if (users.find(u => u._id == entityId) != null) {;
                const u = users.find(u => u._id == entityId)!;
                return `${u.firstName} ${u.lastName}`;
            } else {
                return entityId;
            }
        } else if (entityType == AuditLogEntityType.Role) {
            return roles.find(r => r._id == entityId)?.name ?? entityId;
        } else if (entityType == AuditLogEntityType.OAuthApplication) {
            return applications.find(a => a._id == entityId)?.name ?? entityId;
        } else {
            return "Unknown";
        }
    }

    onMount(async () => {
        api.getAuditLogs(user).then((newAuditLogs) => {
            auditLogs = newAuditLogs;
            api.getOAuthApplications().then((newApplications) => {
                applications = newApplications;
            }).catch((err) => {
                console.error(err);
            });
            if (UserMinimal.isAdmin(user)) {
                api.getUsers().then((newUsers) => {
                    users = newUsers;
                }).catch((err) => {
                    console.error(err);
                });
            }
        }).catch((err) => {
            console.error(err);
        });
    })
</script>

<div class="flex flex-col overflow-y-scroll border-[2px] border-[#222] rounded-md p-4">
    <table>
        <thead>
            <tr>
                <th>Entity</th>
                <th>Type</th>
                <th>Action</th>
                <th>Reason</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody class="text-center">
            {#each auditLogs.reverse() as log}
                <tr>
                    <td>{getEntityName(log.entityType, log.entityId)}</td>
                    <td>{log.entityType}</td>
                    <td>{log.action}</td>
                    <td>{log.reason}</td>
                    <td>{AuditLog.getCreatedAt(log).getDate()}.{AuditLog.getCreatedAt(log).getMonth() + 1}.{AuditLog.getCreatedAt(log).getFullYear()} {AuditLog.getCreatedAt(log).getHours()}:{AuditLog.getCreatedAt(log).getMinutes()}:{AuditLog.getCreatedAt(log).getSeconds()}</td>
                </tr>
            {/each}
        </tbody>
    </table>
</div>

<style>
    table {
        width: 100%;
    }

    th, td {
        border: 2px solid #222;
        padding: 10px;
        text-align: center;
    }

    ::-webkit-scrollbar {
        width: 5px;
    }

    ::-webkit-scrollbar-thumb {
        background-color: var(--color-blue-500);
        border-radius: 10px;
    }
</style>