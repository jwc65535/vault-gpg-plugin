package gpg

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDecrypt(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("name"),
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
				Description: "Optional list of items for batch decryption. Each item must contain a \"ciphertext\" key and may contain an optional \"signer_key\" (ASCII-armored public key). When present, returns \"batch_results\" instead of a single \"plaintext\".",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptWrite,
			},
		},
		HelpSynopsis:    pathDecryptHelpSyn,
		HelpDescription: pathDecryptHelpDesc,
	}
}

func (b *backend) pathDecryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
			requireSignature := false
			if sk, ok := item["signer_key"].(string); ok && sk != "" {
				el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(sk))
				if err != nil {
					results[i] = map[string]interface{}{"error": err.Error()}
					continue
				}
				itemKeyring = append(append(openpgp.EntityList{}, keyring...), el[0])
				requireSignature = true
			}
			plaintext, err := decryptOne(itemKeyring, ciphertext, format, requireSignature)
			if err != nil {
				results[i] = map[string]interface{}{"error": err.Error()}
				continue
			}
			results[i] = map[string]interface{}{"plaintext": plaintext}
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

	plaintext, err := decryptOne(keyring, data.Get("ciphertext").(string), format, signerKey != "")
	if err != nil {
		switch e := err.(type) {
		case decryptInternalErr:
			return nil, e.error
		case decryptSoftErr:
			return logical.ErrorResponse(e.Error()), nil
		default:
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": plaintext,
		},
	}, nil
}

// decryptInternalErr wraps errors that should surface as 500 (unexpected I/O
// failures on the already-decrypted body, matching the original handler behaviour).
type decryptInternalErr struct{ error }

// decryptSoftErr wraps errors that should produce a 400 with a nil second
// return value (signature validation failure, matching the original handler).
type decryptSoftErr struct{ error }

func decryptOne(keyring openpgp.EntityList, ciphertext, format string, requireSignature bool) (string, error) {
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

	md, err := openpgp.ReadMessage(ciphertextDecoder, keyring, nil, nil)
	if err != nil {
		return "", err
	}

	var plaintext bytes.Buffer
	w := base64.NewEncoder(base64.StdEncoding, &plaintext)
	if _, err = io.Copy(w, md.UnverifiedBody); err != nil {
		return "", decryptInternalErr{err}
	}
	if err = w.Close(); err != nil {
		return "", decryptInternalErr{err}
	}

	if requireSignature && (!md.IsSigned || md.SignedBy == nil || md.SignatureError != nil) {
		//nolint:staticcheck // ST1005: capitalization matches the original upstream error string; changing it would break callers
		return "", decryptSoftErr{fmt.Errorf("Signature is invalid or not present: %s", md.SignatureError)}
	}

	return plaintext.String(), nil
}

const pathDecryptHelpSyn = "Decrypt a ciphertext value using a named GPG key"

const pathDecryptHelpDesc = `
This path uses the named GPG key from the request path to decrypt a user
provided ciphertext. The plaintext is returned base64 encoded.
`
