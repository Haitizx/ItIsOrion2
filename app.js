import * as openpgp from "https://cdn.jsdelivr.net/npm/openpgp@5.11.2/+esm";

const $ = (id) => document.getElementById(id);

const els = {
  blob: $("blob"),
  pubkey: $("pubkey"),
  verify: $("verify"),
  status: $("status"),
  meta: $("meta"),
};

function setStatus(kind, text, meta = "") {
  els.status.textContent = text;
  els.meta.textContent = meta;

  els.status.style.color =
    kind === "ok" ? "var(--ok)" :
    kind === "bad" ? "var(--bad)" :
    kind === "warn" ? "var(--warn)" :
    "var(--text)";
}

function extractArmoredBlocks(blob) {
  // captura blocos ASCII armor inteiros
  const re = /-----BEGIN PGP ([A-Z ]+)-----[\s\S]*?-----END PGP \1-----/g;
  const blocks = [];
  let m;
  while ((m = re.exec(blob)) !== null) {
    blocks.push({ type: m[1], armored: m[0] });
  }
  return blocks;
}

function summarizeKey(publicKey) {
  const userIDs = publicKey.getUserIDs ? publicKey.getUserIDs() : [];
  const fp = publicKey.getFingerprint ? publicKey.getFingerprint() : "";
  const alg = publicKey.getAlgorithmInfo ? publicKey.getAlgorithmInfo() : null;

  return {
    fingerprint: fp,
    userIDs,
    algorithm: alg ? `${alg.algorithm} (${alg.bits} bits)` : "—",
  };
}

function formatMeta({ publicKey, signature }) {
  const k = summarizeKey(publicKey);
  const created = signature?.signature?.created ? new Date(signature.signature.created).toISOString() : "—";
  const keyID = signature?.keyID ? String(signature.keyID) : "—";

  return [
    `Fingerprint (key): ${k.fingerprint || "—"}`,
    `User IDs: ${k.userIDs?.length ? k.userIDs.join(" | ") : "—"}`,
    `Key algorithm: ${k.algorithm}`,
    `Signature created: ${created}`,
    `KeyID (signature): ${keyID}`,
  ].join("\n");
}

async function verifyCleartext(armoredPublicKey, signedMessageArmored) {
  const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const message = await openpgp.readCleartextMessage({ cleartextMessage: signedMessageArmored });

  const result = await openpgp.verify({
    message,
    verificationKeys: publicKey,
  });

  const sig = result.signatures[0];
  await sig.verified;
  return { publicKey, signature: sig, mode: "cleartext" };
}

async function verifyDetached(armoredPublicKey, messageText, signatureArmored) {
  const publicKey = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const message = await openpgp.createMessage({ text: messageText });
  const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });

  const result = await openpgp.verify({
    message,
    signature,
    verificationKeys: publicKey,
  });

  const sig = result.signatures[0];
  await sig.verified;
  return { publicKey, signature: sig, mode: "detached" };
}

function stripArmoredBlocks(blob) {
  // remove qualquer bloco armor e deixa “o resto” como possível texto assinado (detached)
  return blob.replace(/-----BEGIN PGP ([A-Z ]+)-----[\s\S]*?-----END PGP \1-----/g, "").trim();
}

els.verify.addEventListener("click", async () => {
  const blob = els.blob.value;
  const fallbackPub = els.pubkey.value.trim();

  if (!blob.trim()) {
    setStatus("warn", "Cole algum conteúdo.", "");
    return;
  }

  try {
    setStatus("neutral", "Analisando…", "");

    const blocks = extractArmoredBlocks(blob);

    // 1) chave pública: pode estar no blob ou no campo avançado
    const pubBlock = blocks.find(b => b.type === "PUBLIC KEY BLOCK")?.armored || fallbackPub;
    if (!pubBlock || !pubBlock.includes("BEGIN PGP PUBLIC KEY BLOCK")) {
      setStatus(
        "warn",
        "Não achei a chave pública. Cole junto no texto (PUBLIC KEY BLOCK) ou use Opções avançadas.",
        ""
      );
      return;
    }

    // 2) Se tiver SIGNED MESSAGE no blob, é cleartext (verificação direta)
    const hasSigned = blob.includes("BEGIN PGP SIGNED MESSAGE");
    if (hasSigned) {
      // aqui é importante: usar o blob inteiro que contém o signed message
      // (o readCleartextMessage lida com o bloco completo)
      const signedStart = blob.indexOf("-----BEGIN PGP SIGNED MESSAGE-----");
      const signedArmored = blob.slice(signedStart).trim();

      const out = await verifyCleartext(pubBlock, signedArmored);
      setStatus("ok", `✅ Assinatura VÁLIDA (${out.mode})`, formatMeta(out));
      return;
    }

    // 3) Caso contrário, tente detached:
    // precisa de uma SIGNATURE armor + o texto (fora dos blocos)
    const sigBlock = blocks.find(b => b.type === "SIGNATURE")?.armored;
    if (!sigBlock) {
      setStatus("warn", "Não achei bloco de assinatura (BEGIN PGP SIGNATURE).", "");
      return;
    }

    // texto “mensagem” = tudo fora dos blocos armor
    const msgText = stripArmoredBlocks(blob);

    if (!msgText) {
      setStatus(
        "warn",
        "Achei a assinatura, mas não achei texto de mensagem fora dos blocos. Para detached, cole também o texto original junto.",
        ""
      );
      return;
    }

    const out = await verifyDetached(pubBlock, msgText, sigBlock);
    setStatus("ok", `✅ Assinatura VÁLIDA (${out.mode})`, formatMeta(out));
  } catch (e) {
    setStatus("bad", "❌ Assinatura INVÁLIDA (ou dados inconsistentes)", String(e));
  }
});