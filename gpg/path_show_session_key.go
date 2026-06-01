package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathShowSessionKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "show-session-key/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "The ciphertext to decrypt",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the ciphertext uses. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
			"signer_key": {
				Type:        framework.TypeString,
				Description: "The ASCII-armored GPG key of the signer of the ciphertext. If present, the signature must be valid.",
			},
			"batch_input": {
				Type:        framework.TypeSlice,
				Description: "Optional list of items for batch session key extraction. Each item must contain a \"ciphertext\" key and may contain an optional \"signer_key\" (ASCII-armored public key). When present, returns \"batch_results\" instead of a single \"session_key\".",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathShowSessionKeyWrite,
			},
		},
		HelpSynopsis:    pathDecryptSessionKeyHelpSyn,
		HelpDescription: pathDecryptSessionKeyHelpDesc,
	}
}

func (b *backend) pathShowSessionKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"base64\" or \"ascii-armor\"", format)), nil
	}

	keyEntry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	r := bytes.NewReader(keyEntry.SerializedKey)
	keyring, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	if rawBatch, ok := data.GetOk("batch_input"); ok {
		items := rawBatch.([]interface{})
		results := make([]map[string]interface{}, len(items))
		for i, raw := range items {
			item, ok := raw.(map[string]interface{})
			if !ok {
				results[i] = map[string]interface{}{"error": "invalid item format"}
				continue
			}
			ciphertext, ok := item["ciphertext"].(string)
			if !ok {
				results[i] = map[string]interface{}{"error": "missing or invalid ciphertext"}
				continue
			}
			itemKeyring := keyring
			if sk, ok := item["signer_key"].(string); ok && sk != "" {
				el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(sk))
				if err != nil {
					results[i] = map[string]interface{}{"error": err.Error()}
					continue
				}
				itemKeyring = append(append(openpgp.EntityList{}, keyring...), el[0])
			}
			sk, err := showSessionKeyOne(itemKeyring, ciphertext, format)
			if err != nil {
				results[i] = map[string]interface{}{"error": err.Error()}
				continue
			}
			results[i] = map[string]interface{}{"session_key": sk}
		}
		return &logical.Response{Data: map[string]interface{}{"batch_results": results}}, nil
	}

	signerKey := data.Get("signer_key").(string)
	if signerKey != "" {
		el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(signerKey))
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		keyring = append(keyring, el[0])
	}

	sk, err := showSessionKeyOne(keyring, data.Get("ciphertext").(string), format)
	if err != nil {
		switch e := err.(type) {
		case decryptSoftErr:
			return logical.ErrorResponse(e.Error()), nil
		default:
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"session_key": sk,
		},
	}, nil
}

func showSessionKeyOne(keyring openpgp.EntityList, ciphertext, format string) (string, error) {
	ciphertextEncoded := strings.NewReader(ciphertext)
	var ciphertextDecoder io.Reader
	switch format {
	case "base64":
		ciphertextDecoder = base64.NewDecoder(base64.StdEncoding, ciphertextEncoded)
	case "ascii-armor":
		block, err := armor.Decode(ciphertextEncoded)
		if err != nil {
			return "", err
		}
		ciphertextDecoder = block.Body
	}

	for {
		p, err := packet.Read(ciphertextDecoder)
		if err == io.EOF {
			//nolint:ST1005 // capitalization matches the original upstream error string; changing it would break callers
			return "", decryptSoftErr{fmt.Errorf("Unable to decrypt session key")}
		}
		if err != nil {
			return "", err
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			encryptedKey := *p
			keys := keyring.KeysById(encryptedKey.KeyId)
			for _, key := range keys {
				encryptedKey.Decrypt(key.PrivateKey, nil)
				if len(encryptedKey.Key) > 0 {
					return fmt.Sprintf("%d:%s", encryptedKey.CipherFunc, strings.ToUpper(hex.EncodeToString(encryptedKey.Key))), nil
				}
			}
		}
	}
}

const pathDecryptSessionKeyHelpSyn = "Decrypt a session key of a message using a named GPG key"

const pathDecryptSessionKeyHelpDesc = `
This path uses the named GPG key from the request path to decrypt the session key of a message. 
`
