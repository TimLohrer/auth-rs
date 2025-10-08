<script lang="ts">
	import { SCOPES } from "$lib/models/OAuthScopes";
    import {
        Link,
        User,
        UserPen,
        UserMinus,
        UserCog,
        Crown,
        ClipboardList,
        CodeXml,
        Unlink,
		FolderOpen,
		FolderPen,
		FolderCog
    } from "lucide-svelte";

    export let scopes: string[];
    export let gap: string = "15px";
    export let iconSize: number = 25;
    export let textSize: string = "14px";
</script>

{#each scopes as scope}
    <div class="flex flex-row items-center w-full gap-[{gap}]">
        {#if SCOPES[scope].icon == 'user'}
            <User size={iconSize} />
        {:else if SCOPES[scope].icon == 'folder-open'}
            <FolderOpen size={iconSize} />
        {:else if SCOPES[scope].icon == 'folder-pen'}
            <FolderPen size={iconSize} />
        {:else if SCOPES[scope].icon == 'folder-cog'}
            <FolderCog size={iconSize} />
        {:else if SCOPES[scope].icon == 'user-pen'}
            <UserPen size={iconSize} />
        {:else if SCOPES[scope].icon == 'user-minus'}
            <UserMinus size={iconSize} />
        {:else if SCOPES[scope].icon == 'user-cog'}
            <UserCog size={iconSize} />
        {:else if SCOPES[scope].icon == 'crown'}
            <Crown size={iconSize} />
        {:else if SCOPES[scope].icon == 'clipboard-list'}
            <ClipboardList size={iconSize} />
        {:else if SCOPES[scope].icon == 'code-xml'}
            <CodeXml size={iconSize} />
        {:else if SCOPES[scope].icon == 'link'}
            <Link size={iconSize} />
        {:else if SCOPES[scope].icon == 'unlink'}
            <Unlink size={iconSize} />
        {/if}
        <p class="text-[{textSize}]">{SCOPES[scope].description}</p>
    </div>
{/each}