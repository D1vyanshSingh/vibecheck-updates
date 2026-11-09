import { AcceptInvite } from "@/components/auth/AcceptInvite";

export const metadata = { title: "Workspace invitation" };

export default async function InvitePage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;

  return (
    <section className="panel p-7">
      <p className="eyebrow-plain mb-3">Workspace invitation</p>
      <h1 className="display-sub text-fog">Join this workspace</h1>
      <p className="body-copy mt-2 text-[13.5px]">
        Accepting adds your account to the workspace with the role the inviter
        assigned. Invitations expire seven days after they are created and can only
        be used once.
      </p>
      <div className="mt-6">
        <AcceptInvite token={token} />
      </div>
    </section>
  );
}
