package gpg

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestGPG_SignVerify(t *testing.T) {
	var b *backend
	storage := &logical.InmemStorage{}

	b = Backend()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	}
	req2 := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test2",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test2",
			"email":     "vault@example.com",
		},
	}
	req3 := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test3",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test3",
			"email":     "vault@example.com",
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), req3)
	if err != nil {
		t.Fatal(err)
	}

	signRequest := func(req *logical.Request, keyName string, errExpected bool, postpath string) string {
		req.Path = "sign/" + keyName + postpath
		response, err := b.HandleRequest(context.Background(), req)
		if err != nil && !errExpected {
			t.Fatal(err)
		}
		if response == nil {
			t.Fatal("expected non-nil response")
		}
		if errExpected {
			if !response.IsError() {
				t.Fatalf("expected error response: %#v", *response)
			}
			return ""
		}
		if response.IsError() {
			t.Fatalf("not expected error response: %#v", *response)
		}
		signature, ok := response.Data["signature"]
		if !ok {
			t.Fatalf("no signature found in response data: %#v", response.Data)
		}
		return signature.(string)
	}

	verifyRequest := func(req *logical.Request, keyName string, errExpected, validSignature bool, signature string) {
		req.Path = "verify/" + keyName
		req.Data["signature"] = signature
		response, err := b.HandleRequest(context.Background(), req)
		if err != nil && !errExpected {
			t.Fatalf("error: %v, signature was %v", err, signature)
		}
		if errExpected {
			if response != nil && !response.IsError() {
				t.Fatalf("expected error response: %#v", *response)
			}
			return
		}
		if response == nil {
			t.Fatal("expected non-nil response")
		}
		if response.IsError() {
			t.Fatalf("not expected error response: %#v", *response)
		}
		value, ok := response.Data["valid"]
		if !ok {
			t.Fatalf("no valid key found in response data %#v", response.Data)
		}
		if validSignature && !value.(bool) {
			t.Fatalf("not expected failing signature verification %#v %#v", *req, *response)
		}
		if !validSignature && value.(bool) {
			t.Fatalf("expected failing signature verification %#v %#v", *req, *response)
		}
	}

	req.Data = map[string]interface{}{
		"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
	}

	// Test defaults
	signature := signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)
	verifyRequest(req, "test2", false, false, signature)

	// Test algorithm selection in path
	signature = signRequest(req, "test", false, "/sha2-224")
	verifyRequest(req, "test", false, true, signature)

	// Test algorithm selection in the data
	req.Data["algorithm"] = "sha2-224"
	signature = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "sha2-384"
	signature = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "sha2-512"
	signature = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	req.Data["algorithm"] = "notexisting"
	signRequest(req, "test", true, "")
	delete(req.Data, "algorithm")

	// Test format selection
	req.Data["format"] = "ascii-armor"
	signature = signRequest(req, "test", false, "")
	verifyRequest(req, "test", false, true, signature)

	// Test validation format mismatch
	req.Data["format"] = "ascii-armor"
	signature = signRequest(req, "test", false, "")
	req.Data["format"] = "base64"
	verifyRequest(req, "test", false, false, signature)

	// Test bad format
	req.Data["format"] = "notexisting"
	signRequest(req, "test", true, "")
	verifyRequest(req, "test", true, true, signature)
	delete(req.Data, "format")

	// Test non existent key
	signRequest(req, "notfound", true, "")
	verifyRequest(req, "notfound", true, false, signature)

	// Test bad input
	req.Data["input"] = "foobar"
	signRequest(req, "test", true, "")
	verifyRequest(req, "test", true, false, signature)
}

func TestGPG_SignBatch_Success(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
				map[string]interface{}{"input": "aGVsbG8gd29ybGQ="},
				map[string]interface{}{"input": "Zm9v"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T: %v", resp.Data["batch_results"], resp.Data["batch_results"])
	}
	if len(batchResults) != 3 {
		t.Fatalf("expected 3 batch results, got %d", len(batchResults))
	}
	for i, result := range batchResults {
		if _, hasError := result["error"]; hasError {
			t.Errorf("item %d: unexpected error: %v", i, result["error"])
		}
		if _, hasSig := result["signature"]; !hasSig {
			t.Errorf("item %d: missing signature", i)
		}
	}
}

func TestGPG_SignBatch_PartialError(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
				map[string]interface{}{"input": "!!not-valid-base64!!"},
				map[string]interface{}{"input": "Zm9v"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", resp.Data["batch_results"])
	}
	if len(batchResults) != 3 {
		t.Fatalf("expected 3 batch results, got %d", len(batchResults))
	}
	for _, i := range []int{0, 2} {
		if _, hasError := batchResults[i]["error"]; hasError {
			t.Errorf("item %d: unexpected error: %v", i, batchResults[i]["error"])
		}
		if _, hasSig := batchResults[i]["signature"]; !hasSig {
			t.Errorf("item %d: missing signature", i)
		}
	}
	if _, hasError := batchResults[1]["error"]; !hasError {
		t.Errorf("item 1: expected error, got: %v", batchResults[1])
	}
	if _, hasSig := batchResults[1]["signature"]; hasSig {
		t.Errorf("item 1: unexpected signature present")
	}
}

func TestGPG_SignBatch_Empty(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T: %v", resp.Data["batch_results"], resp.Data["batch_results"])
	}
	if len(batchResults) != 0 {
		t.Fatalf("expected 0 batch results, got %d", len(batchResults))
	}
}

func TestGPG_SignBatch_RequestLevelBadFormat(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]interface{}{
			"format": "notexisting",
			"batch_input": []interface{}{
				map[string]interface{}{"input": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
			},
		},
	})
	if err != nil && err != logical.ErrInvalidRequest {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got: %v", resp)
	}
	if _, hasBatch := resp.Data["batch_results"]; hasBatch {
		t.Errorf("expected no batch_results in error response")
	}
}

func TestGPG_SignBatch_RequestLevelUnknownKey(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/doesnotexist",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
			},
		},
	})
	if err != nil && err != logical.ErrInvalidRequest {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got: %v", resp)
	}
	if _, hasBatch := resp.Data["batch_results"]; hasBatch {
		t.Errorf("expected no batch_results in error response")
	}
}

func TestGPG_SignBatch_SignaturesAreVerifiable(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data: map[string]interface{}{
			"real_name": "Vault GPG test",
			"email":     "vault@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	inputs := []string{
		"dGhlIHF1aWNrIGJyb3duIGZveA==",
		"aGVsbG8gd29ybGQ=",
		"Zm9v",
	}
	batchItems := make([]interface{}, len(inputs))
	for i, input := range inputs {
		batchItems[i] = map[string]interface{}{"input": input}
	}

	signResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data: map[string]interface{}{
			"batch_input": batchItems,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if signResp.IsError() {
		t.Fatalf("expected no error response, got: %v", signResp)
	}

	batchResults, ok := signResp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", signResp.Data["batch_results"])
	}

	for i, result := range batchResults {
		sig, ok := result["signature"].(string)
		if !ok {
			t.Fatalf("item %d: missing or invalid signature", i)
		}
		verifyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "verify/test",
			Data: map[string]interface{}{
				"input":     inputs[i],
				"signature": sig,
			},
		})
		if err != nil {
			t.Fatalf("item %d: verify error: %v", i, err)
		}
		if verifyResp.IsError() {
			t.Fatalf("item %d: verify returned error response: %v", i, verifyResp)
		}
		valid, ok := verifyResp.Data["valid"].(bool)
		if !ok {
			t.Fatalf("item %d: missing valid field in verify response", i)
		}
		if !valid {
			t.Errorf("item %d: signature not valid", i)
		}
	}
}

func TestGPG_VerifyBatch_Success(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	inputs := []string{
		"dGhlIHF1aWNrIGJyb3duIGZveA==",
		"aGVsbG8gd29ybGQ=",
		"Zm9v",
	}
	signatures := make([]string, len(inputs))
	for i, input := range inputs {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "sign/test",
			Data:      map[string]interface{}{"input": input},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("sign item %d: unexpected error: %v", i, resp)
		}
		signatures[i] = resp.Data["signature"].(string)
	}

	batchItems := make([]interface{}, len(inputs))
	for i := range inputs {
		batchItems[i] = map[string]interface{}{
			"input":     inputs[i],
			"signature": signatures[i],
		}
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data:      map[string]interface{}{"batch_input": batchItems},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T: %v", resp.Data["batch_results"], resp.Data["batch_results"])
	}
	if len(batchResults) != 3 {
		t.Fatalf("expected 3 batch results, got %d", len(batchResults))
	}
	for i, result := range batchResults {
		if _, hasError := result["error"]; hasError {
			t.Errorf("item %d: unexpected error: %v", i, result["error"])
		}
		valid, ok := result["valid"].(bool)
		if !ok {
			t.Errorf("item %d: missing or invalid 'valid' field", i)
		} else if !valid {
			t.Errorf("item %d: expected valid=true", i)
		}
	}
}

func TestGPG_VerifyBatch_InvalidSignature(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	input := "dGhlIHF1aWNrIGJyb3duIGZveA=="
	signResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data:      map[string]interface{}{"input": input},
	})
	if err != nil {
		t.Fatal(err)
	}
	validSig := signResp.Data["signature"].(string)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": input, "signature": validSig},
				map[string]interface{}{"input": input, "signature": "invalidsignaturedata"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", resp.Data["batch_results"])
	}
	if len(batchResults) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(batchResults))
	}

	if _, hasError := batchResults[0]["error"]; hasError {
		t.Errorf("item 0: unexpected error: %v", batchResults[0]["error"])
	}
	if valid, ok := batchResults[0]["valid"].(bool); !ok || !valid {
		t.Errorf("item 0: expected valid=true, got: %v", batchResults[0])
	}

	if _, hasError := batchResults[1]["error"]; hasError {
		t.Errorf("item 1: invalid signature must produce valid=false, not an error entry: %v", batchResults[1]["error"])
	}
	if valid, ok := batchResults[1]["valid"].(bool); !ok {
		t.Errorf("item 1: missing 'valid' field, got: %v", batchResults[1])
	} else if valid {
		t.Errorf("item 1: expected valid=false for invalid signature")
	}
}

func TestGPG_VerifyBatch_PartialMissingInput(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	input := "dGhlIHF1aWNrIGJyb3duIGZveA=="
	signResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data:      map[string]interface{}{"input": input},
	})
	if err != nil {
		t.Fatal(err)
	}
	validSig := signResp.Data["signature"].(string)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": input, "signature": validSig},
				map[string]interface{}{"signature": validSig}, // no "input" key
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", resp.Data["batch_results"])
	}
	if len(batchResults) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(batchResults))
	}
	if _, hasValid := batchResults[0]["valid"]; !hasValid {
		t.Errorf("item 0: missing 'valid' key, got: %v", batchResults[0])
	}
	if _, hasError := batchResults[1]["error"]; !hasError {
		t.Errorf("item 1: expected 'error' key, got: %v", batchResults[1])
	}
	if _, hasValid := batchResults[1]["valid"]; hasValid {
		t.Errorf("item 1: unexpected 'valid' key in error result")
	}
}

func TestGPG_VerifyBatch_PartialBadInputBase64(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	input := "dGhlIHF1aWNrIGJyb3duIGZveA=="
	signResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "sign/test",
		Data:      map[string]interface{}{"input": input},
	})
	if err != nil {
		t.Fatal(err)
	}
	validSig := signResp.Data["signature"].(string)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]interface{}{
			"batch_input": []interface{}{
				map[string]interface{}{"input": input, "signature": validSig},
				map[string]interface{}{"input": "!!bad!!", "signature": validSig},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", resp.Data["batch_results"])
	}
	if len(batchResults) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(batchResults))
	}
	if _, hasValid := batchResults[0]["valid"]; !hasValid {
		t.Errorf("item 0: missing 'valid' key, got: %v", batchResults[0])
	}
	if _, hasError := batchResults[1]["error"]; !hasError {
		t.Errorf("item 1: expected 'error' key, got: %v", batchResults[1])
	}
	if _, hasValid := batchResults[1]["valid"]; hasValid {
		t.Errorf("item 1: unexpected 'valid' key in error result")
	}
}

func TestGPG_VerifyBatch_Empty(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data:      map[string]interface{}{"batch_input": []interface{}{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T: %v", resp.Data["batch_results"], resp.Data["batch_results"])
	}
	if len(batchResults) != 0 {
		t.Fatalf("expected 0 batch results, got %d", len(batchResults))
	}
}

func TestGPG_VerifyBatch_RequestLevelBadFormat(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/test",
		Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test",
		Data: map[string]interface{}{
			"format": "notexisting",
			"batch_input": []interface{}{
				map[string]interface{}{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "signature": "somesig"},
			},
		},
	})
	if err != nil && err != logical.ErrInvalidRequest {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got: %v", resp)
	}
	if _, hasBatch := resp.Data["batch_results"]; hasBatch {
		t.Errorf("expected no batch_results in error response")
	}
}

func TestGPG_VerifyBatch_CrossKeyAllInvalid(t *testing.T) {
	storage := &logical.InmemStorage{}
	b := Backend()

	for _, name := range []string{"test", "test2"} {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "keys/" + name,
			Data:      map[string]interface{}{"real_name": "Vault GPG test", "email": "vault@example.com"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	inputs := []string{"dGhlIHF1aWNrIGJyb3duIGZveA==", "aGVsbG8gd29ybGQ="}
	batchItems := make([]interface{}, len(inputs))
	for i, input := range inputs {
		signResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "sign/test",
			Data:      map[string]interface{}{"input": input},
		})
		if err != nil {
			t.Fatal(err)
		}
		batchItems[i] = map[string]interface{}{
			"input":     input,
			"signature": signResp.Data["signature"].(string),
		}
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "verify/test2",
		Data:      map[string]interface{}{"batch_input": batchItems},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("expected no error response, got: %v", resp)
	}

	batchResults, ok := resp.Data["batch_results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected batch_results to be []map[string]interface{}, got %T", resp.Data["batch_results"])
	}
	if len(batchResults) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(batchResults))
	}
	for i, result := range batchResults {
		if _, hasError := result["error"]; hasError {
			t.Errorf("item %d: cross-key invalid sig must be valid=false, not an error: %v", i, result["error"])
		}
		valid, ok := result["valid"].(bool)
		if !ok {
			t.Errorf("item %d: missing 'valid' field", i)
		} else if valid {
			t.Errorf("item %d: expected valid=false for cross-key verification", i)
		}
	}
}
