package gpg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("urlalgorithm"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data",
			},
			"urlalgorithm": {
				Type:        framework.TypeString,
				Description: "Hash algorithm to use (POST URL parameter)",
			},
			"algorithm": {
				Type:    framework.TypeString,
				Default: "sha2-256",
				Description: `Hash algorithm to use (POST body parameter). Valid values are:

* sha2-224
* sha2-256
* sha2-384
* sha2-512

Defaults to "sha2-256".`,
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format to use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
			"batch_input": {
				Type:        framework.TypeSlice,
				Description: "Optional list of items for batch signing. Each item must contain an \"input\" key with a base64-encoded value. When present, returns \"batch_results\" instead of a single \"signature\".",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignWrite,
			},
		},
		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func pathVerify(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "verify/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The key to use",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The base64-encoded input data to verify",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The signature",
			},
			"format": {
				Type:        framework.TypeString,
				Default:     "base64",
				Description: `Encoding format the signature use. Can be "base64" or "ascii-armor". Defaults to "base64".`,
			},
			"batch_input": {
				Type:        framework.TypeSlice,
				Description: "Optional list of items for batch verification. Each item must contain \"input\" (base64-encoded data) and \"signature\" keys. When present, returns \"batch_results\" instead of a single \"valid\".",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVerifyWrite,
			},
		},
		HelpSynopsis:    pathVerifyHelpSyn,
		HelpDescription: pathVerifyHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

	config := packet.Config{}

	algorithm := data.Get("urlalgorithm").(string)
	if algorithm == "" {
		algorithm = data.Get("algorithm").(string)
	}
	switch algorithm {
	case "sha2-224":
		config.DefaultHash = crypto.SHA224
	case "sha2-256":
		config.DefaultHash = crypto.SHA256
	case "sha2-384":
		config.DefaultHash = crypto.SHA384
	case "sha2-512":
		config.DefaultHash = crypto.SHA512
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported algorithm %s", algorithm)), nil
	}

	format := data.Get("format").(string)
	switch format {
	case "base64":
	case "ascii-armor":
	default:
		return logical.ErrorResponse(fmt.Sprintf("unsupported encoding format %s; must be \"base64\" or \"ascii-armor\"", format)), nil
	}

	entry, err := b.key(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	entity, err := b.entity(entry)
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
			inputB64, ok := item["input"].(string)
			if !ok {
				results[i] = map[string]interface{}{"error": "missing or invalid input"}
				continue
			}
			itemInput, err := base64.StdEncoding.DecodeString(inputB64)
			if err != nil {
				results[i] = map[string]interface{}{"error": fmt.Sprintf("unable to decode input as base64: %s", err)}
				continue
			}
			sig, err := signOne(entity, itemInput, config, format)
			if err != nil {
				results[i] = map[string]interface{}{"error": err.Error()}
				continue
			}
			results[i] = map[string]interface{}{"signature": sig}
		}
		return &logical.Response{Data: map[string]interface{}{"batch_results": results}}, nil
	}

	sig, err := signOne(entity, input, config, format)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": sig,
		},
	}, nil
}

func signOne(entity *openpgp.Entity, input []byte, config packet.Config, format string) (string, error) {
	var armoredSignatureBuffer bytes.Buffer
	err := openpgp.ArmoredDetachSign(&armoredSignatureBuffer, entity, bytes.NewReader(input), &config)
	if err != nil {
		return "", err
	}

	var outputSignature bytes.Buffer
	switch format {
	case "ascii-armor":
		outputSignature = armoredSignatureBuffer
	case "base64":
		block, err := armor.Decode(bytes.NewReader(armoredSignatureBuffer.Bytes()))
		if err != nil {
			return "", err
		}

		encoder := base64.NewEncoder(base64.StdEncoding, &outputSignature)
		bufBody := &bytes.Buffer{}
		_, err = bufBody.ReadFrom(block.Body)
		if err != nil {
			return "", err
		}
		_, err = encoder.Write(bufBody.Bytes())
		if err != nil {
			return "", err
		}
		err = encoder.Close()
		if err != nil {
			return "", err
		}
	}

	return outputSignature.String(), nil
}

func (b *backend) pathVerifyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	inputB64 := data.Get("input").(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to decode input as base64: %s", err)), logical.ErrInvalidRequest
	}

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
			inputB64, ok := item["input"].(string)
			if !ok {
				results[i] = map[string]interface{}{"error": "missing or invalid input"}
				continue
			}
			itemInput, err := base64.StdEncoding.DecodeString(inputB64)
			if err != nil {
				results[i] = map[string]interface{}{"error": fmt.Sprintf("unable to decode input as base64: %s", err)}
				continue
			}
			sig, ok := item["signature"].(string)
			if !ok {
				results[i] = map[string]interface{}{"error": "missing or invalid signature"}
				continue
			}
			results[i] = map[string]interface{}{"valid": verifyOne(keyring, itemInput, sig, format)}
		}
		return &logical.Response{Data: map[string]interface{}{"batch_results": results}}, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"valid": verifyOne(keyring, input, data.Get("signature").(string), format),
		},
	}, nil
}

func verifyOne(keyring openpgp.EntityList, input []byte, signature, format string) bool {
	sig := strings.NewReader(signature)
	message := bytes.NewReader(input)
	var err error
	switch format {
	case "base64":
		decoder := base64.NewDecoder(base64.StdEncoding, sig)
		_, err = openpgp.CheckDetachedSignature(keyring, message, decoder, nil)
	case "ascii-armor":
		_, err = openpgp.CheckArmoredDetachedSignature(keyring, message, sig, nil)
	}
	return err == nil
}

const pathSignHelpSyn = "Generate a signature for input data using the named GPG key"
const pathSignHelpDesc = "Generates a signature of the input data using the named GPG key."
const pathVerifyHelpSyn = "Verify a signature for input data created using the named GPG key"
const pathVerifyHelpDesc = "Verifies a signature of the input data using the named GPG key."
