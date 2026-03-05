import * as openpgp from "https://cdn.jsdelivr.net/npm/openpgp@5.11.2/+esm";

/**
 * Chave pública fixa do Órion (pra não depender do MIT/keyserver caindo)
 * A ideia é: colou a mensagem assinada → valida com essa key e já era.
 */
const ORION_PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: pgp.mit.edu

mDMEaaE93BYJKwYBBAHaRw8BAQdAb3TkLFB8UvgpzMWNzhncHPb9zRj7uS0sqkVrOLIV75G0
KcOTcmlvbiA8b3Jpb25jb3Jwb3JhdGlvbmJyYXppbEBnbWFpbC5jb20+iLUEExYKAF0WIQS/
hH7Ox4wJQwaqvbG7+onlH/r93QUCaaE93BsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMSwyLDEC
GwMFCQWlX5QFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQu/qJ5R/6/d3o4AD+K2j3
yAsk9uhU9GTKpazESzq8+dcjztrsG/Tdc4UsFBkBALXGQ7R/qnarXD3B/XPl+7tvfUJVc2pN
ZdYpR0rwVAoNuDgEaaE93BIKKwYBBAGXVQEFAQEHQIsATlwZXAq2eeCCkFuvgTYeJV6N2OJi
jooNMFLsKBI8AwEIB4iaBBgWCgBCFiEEv4R+zseMCUMGqr2xu/qJ5R/6/d0FAmmhPdwbFIAA
AAAABAAObWFudTIsMi41KzEuMTEsMiwxAhsMBQkFpV+UAAoJELv6ieUf+v3dgP8A/2YNuc/X
6Shl0BBEvj4hf38L/GvC26t4TUafDJqVPNqRAQDBX9yhgE5xH60NncgS1XA0weoI8Yrvv2SE
RRgsy9KCAQ==
=289i
-----END PGP PUBLIC KEY BLOCK-----`;

/**
 * Fingerprint “fixado” (anti-troll / anti-troca de chave).
 * Isso aqui saiu daquele pedaço base64 "v4R+zseMCUMGqr2xu/qJ5R/6/d0" => hex:
 * bf847ecec78c094306aabdb1bbfa89e51ffafddd
 */
const ORION_FINGERPRINT = "BF847ECEC78C094306AABDB1BBFA89E51FFAFDDD";

const $ = (id) => document.getElementById(id);

const els = {
  blob: $("blob"),
  pubkey: $("pubkey"), // pode nem existir mais, de boa
  verify: $("verify"),
  status: $("status"),
  meta: $("meta"),
};

function setStatus(kind, text, meta = "") {
  if (els.status) els.status.textContent = text;
  if (els.meta) els.meta.textContent = meta;

  // corzinha baseada no CSS vars que vc já usou
  if (els.status) {
    els.status.style.color =
      kind === "ok" ? "var(--ok)" :
      kind === "bad" ? "var(--bad)" :
      kind === "warn" ? "var(--warn)" :
      "var(--text)";
  }
}

function extractArmoredBlocks(blob) {
  // pega qualquer bloco ascii armor PGP que estiver no texto (public key, signature, etc)
  const re = /-----BEGIN PGP ([A-Z ]+)-----[\s\S]*?-----END PGP \1-----/g;
  const blocks = [];
  let m;
  while ((m = re.exec(blob)) !== null) {
    blocks.push({ type: m[1], armored: m[0] });
  }
  return blocks;
}

function stripArmoredBlocks(blob) {
  // remove blocos armor e deixa só “o resto” (útil pra detached)
  return blob.replace(/-----BEGIN PGP ([A-Z ]+)-----[\s\S]*?-----END PGP \1-----/g, "").trim();
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

function formatMeta({ publicKey, signature, mode }) {
  const k = summarizeKey(publicKey);

  // algumas versões expõem created diferente; aqui é “best effort”
  const created =
    signature?.signature?.created
      ? new Date(signature.signature.created).toISOString()
      : "—";

  // keyID pode ser objeto; tenta pegar um hex bonitinho
  let keyID = "—";
  if (signature?.keyID) {
    try {
      keyID = signature.keyID.toHex ? signature.keyID.toHex() : String(signature.keyID);
    } catch {
      keyID = String(signature.keyID);
    }
  }

  return [
    `Modo: ${mode}`,
    `Fingerprint (key): ${k.fingerprint || "—"}`,
    `User IDs: ${k.userIDs?.length ? k.userIDs.join(" | ") : "—"}`,
    `Key algorithm: ${k.algorithm}`,
    `Signature created: ${created}`,
    `KeyID (signature): ${keyID}`,
  ].join("\n");
}

async function loadOrionKey() {
  // lê a key fixa
  const publicKey = await openpgp.readKey({ armoredKey: ORION_PUBLIC_KEY });

  // confere fingerprint pra garantir que a key embutida é a esperada (paranóia saudável)
  const fp = (publicKey.getFingerprint?.() || "").toUpperCase();
  if (fp && fp !== ORION_FINGERPRINT) {
    // isso aqui só aconteceria se vc colar uma key errada no ORION_PUBLIC_KEY tlgd
    throw new Error(
      `Fingerprint da chave embutida não bate.\nEsperado: ${ORION_FINGERPRINT}\nEncontrado: ${fp}`
    );
  }

  return publicKey;
}

async function verifyCleartextWithOrion(signedMessageArmored) {
  const publicKey = await loadOrionKey();
  const message = await openpgp.readCleartextMessage({ cleartextMessage: signedMessageArmored });

  const result = await openpgp.verify({
    message,
    verificationKeys: publicKey,
  });

  // pode ter mais de 1 assinatura; a gente tenta todas e aceita a primeira que validar
  for (const sig of result.signatures) {
    try {
      await sig.verified;
      return { publicKey, signature: sig, mode: "cleartext" };
    } catch {
      // tenta a próxima
    }
  }

  throw new Error("Nenhuma assinatura válida encontrada (cleartext).");
}

async function verifyDetachedWithOrion(messageText, signatureArmored) {
  const publicKey = await loadOrionKey();
  const message = await openpgp.createMessage({ text: messageText });
  const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });

  const result = await openpgp.verify({
    message,
    signature,
    verificationKeys: publicKey,
  });

  for (const sig of result.signatures) {
    try {
      await sig.verified;
      return { publicKey, signature: sig, mode: "detached" };
    } catch {
      // tenta a próxima
    }
  }

  throw new Error("Assinatura inválida (detached).");
}

// se o botão não existir, não quebra a página
if (els.verify) {
  els.verify.addEventListener("click", async () => {
    const blob = els.blob?.value || "";
    const fallbackPub = els.pubkey?.value?.trim?.() || ""; // não uso mais, mas deixei pq seu html tinha

    if (!blob.trim()) {
      setStatus("warn", "Cole a mensagem assinada do Órion aí.", "");
      return;
    }

    try {
      setStatus("neutral", "Verificando…", "");

      // a key sempre é a do Órion.
      void fallbackPub;

      const blocks = extractArmoredBlocks(blob);

      // 1) cleartext é o caso padrão do ARG (BEGIN PGP SIGNED MESSAGE)
      if (blob.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
        const start = blob.indexOf("-----BEGIN PGP SIGNED MESSAGE-----");
        const signedArmored = blob.slice(start).trim();

        const out = await verifyCleartextWithOrion(signedArmored);

        const fp = (out.publicKey.getFingerprint?.() || "").toUpperCase();
        const okFp = fp === ORION_FINGERPRINT;

        setStatus(
          "ok",
          `✅ Assinatura VÁLIDA (Órion)`,
          formatMeta(out) + `\n\nFingerprint conferido: ${okFp ? "SIM" : "NÃO"}`
        );
        return;
      }

      // 2) se não for cleartext, tenta detached (caso alguém mande só assinatura + texto)
      const sigBlock = blocks.find(b => b.type === "SIGNATURE")?.armored;
      if (!sigBlock) {
        setStatus("warn", "Não achei 'BEGIN PGP SIGNED MESSAGE' nem 'BEGIN PGP SIGNATURE'.", "");
        return;
      }

      const msgText = stripArmoredBlocks(blob);
      if (!msgText) {
        setStatus(
          "warn",
          "Achei a assinatura, mas não achei a mensagem (texto fora dos blocos).",
          "Se for detached, cola a mensagem original junto do bloco de assinatura."
        );
        return;
      }

      const out = await verifyDetachedWithOrion(msgText, sigBlock);

      const fp = (out.publicKey.getFingerprint?.() || "").toUpperCase();
      const okFp = fp === ORION_FINGERPRINT;

      setStatus(
        "ok",
        `✅ Assinatura VÁLIDA (Órion)`,
        formatMeta(out) + `\n\nFingerprint conferido: ${okFp ? "SIM" : "NÃO"}`
      );
    } catch (e) {
      setStatus("bad", "❌ Assinatura INVÁLIDA (ou mensagem alterada)", String(e));
    }
  });
} else {
  // se tu tiver mexido no HTML e sumiu o botão, isso aqui te lembra tlgd
  console.warn("Botão #verify não encontrado. Confere seu HTML.");
}