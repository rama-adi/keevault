const stages = [
  {
    actor: "Deployment",
    title: "Request a boot",
    description: "The client presents its bootstrap token and waits. Your command has not started.",
  },
  {
    actor: "Admin or owner",
    title: "Review and approve",
    description:
      "Check the request against your deployment, then approve with recent passkey verification.",
  },
  {
    actor: "Keevault client",
    title: "Decrypt the environment",
    description: "Open the encrypted payload for this boot and check any required secret names.",
  },
  {
    actor: "Application",
    title: "Start your command",
    description:
      "After the vault confirms receipt, the client launches your command with the secret values.",
  },
];

export function BootFlow() {
  return (
    <figure className="docs-diagram docs-boot-flow">
      <figcaption>From a boot request to a running application</figcaption>
      <ol className="docs-flow-stages">
        {stages.map((stage, index) => (
          <li key={stage.title} className="docs-flow-stage">
            <span className="docs-flow-number" aria-hidden="true">
              {String(index + 1).padStart(2, "0")}
            </span>
            <div>
              <span className="docs-diagram-label">{stage.actor}</span>
              <strong>{stage.title}</strong>
              <p>{stage.description}</p>
            </div>
          </li>
        ))}
      </ol>
      <p className="docs-diagram-note">
        A declined or expired request stops here. Your application does not start.
      </p>
    </figure>
  );
}
