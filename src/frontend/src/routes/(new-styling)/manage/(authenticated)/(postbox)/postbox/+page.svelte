<script lang="ts">
  import { t } from "$lib/stores/locale.store";
  import type { PageProps } from "./$types";
  import type { PostboxEmail } from "$lib/generated/internet_identity_types";

  const { data }: PageProps = $props();

  let selectedIndex = $state(0);
  const emails: PostboxEmail[] = $derived(data.postboxEmails);
  const selectedEmail: PostboxEmail | undefined = $derived(
    emails[selectedIndex],
  );
</script>

<header class="flex flex-col gap-3">
  <h1 class="text-text-primary text-3xl font-medium">
    {$t`Postbox`}
  </h1>
  <p class="text-text-tertiary text-base">
    {$t`Emails received for your identity.`}
  </p>
</header>

<div class="mt-10 flex flex-col gap-6 md:flex-row md:gap-8">
  <!-- Email list -->
  <div
    class="border-border-secondary flex w-full flex-col overflow-hidden rounded-xl border md:w-80 md:shrink-0"
  >
    <ul class="divide-border-secondary divide-y">
      {#each emails as email, i}
        <li class="contents">
          <button
            class={[
              "flex w-full cursor-pointer flex-col gap-1 px-4 py-3 text-left transition-colors",
              i === selectedIndex
                ? "bg-bg-active"
                : "hover:bg-bg-primary_hover",
            ]}
            onclick={() => (selectedIndex = i)}
          >
            <span
              class="text-text-primary truncate text-sm font-medium"
            >
              {email.subject || $t`(no subject)`}
            </span>
            <span class="text-text-tertiary truncate text-xs">
              {email.sender}
            </span>
          </button>
        </li>
      {/each}
    </ul>
  </div>

  <!-- Email content -->
  <div
    class="bg-bg-secondary flex min-h-64 flex-1 flex-col rounded-xl p-6"
  >
    {#if selectedEmail}
      <div class="mb-4 flex flex-col gap-1">
        <h2 class="text-text-primary text-lg font-medium">
          {selectedEmail.subject || $t`(no subject)`}
        </h2>
        <p class="text-text-tertiary text-sm">
          {$t`From:`}
          {selectedEmail.sender}
        </p>
      </div>
      <div class="border-border-secondary border-t pt-4">
        <pre
          class="text-text-secondary whitespace-pre-wrap break-words text-sm">{selectedEmail.body}</pre>
      </div>
    {:else}
      <p class="text-text-tertiary text-sm">
        {$t`No email selected.`}
      </p>
    {/if}
  </div>
</div>
