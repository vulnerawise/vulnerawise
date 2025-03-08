package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Modify the ExportJSON function signature to accept parameters
func ExportJSON(jsonData []byte, outputFilePath string, outputDirPath string, exportBatchSize int) (int, error) {
	// First, count the entries and get metadata without full decode
	var countingStruct struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(jsonData, &countingStruct); err != nil {
		return 0, fmt.Errorf("failed to decode JSON data: %w", err)
	}
	exportedCount := len(countingStruct.Data)

	// Update timestamp while preserving the rest of the JSON structure
	var metadataStruct struct {
		Metadata struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(jsonData, &metadataStruct); err != nil {
		return 0, fmt.Errorf("failed to decode metadata: %w", err)
	}

	// Create an updated timestamp in the exact same format
	metadataStruct.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Marshal just the metadata part
	updatedMetadata, err := json.Marshal(metadataStruct.Metadata)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal updated metadata: %w", err)
	}

	// Replace the metadata in the original JSON without decoding the whole structure
	// This is a simple string replacement that works because we know the structure
	origMetadataStart := bytes.Index(jsonData, []byte(`"metadata":`))
	if origMetadataStart < 0 {
		return 0, fmt.Errorf("malformed JSON: metadata section not found")
	}

	// Find the start and end of the metadata content
	metadataObjStart := bytes.IndexByte(jsonData[origMetadataStart:], '{') + origMetadataStart
	metadataObjEnd := findMatchingCloseBrace(jsonData, metadataObjStart)
	if metadataObjEnd < 0 {
		return 0, fmt.Errorf("malformed JSON: couldn't find end of metadata object")
	}

	// Create the updated JSON by splicing in the new metadata
	updatedJSON := make([]byte, 0, len(jsonData)+100) // pre-allocate with some extra space
	updatedJSON = append(updatedJSON, jsonData[:metadataObjStart+1]...)
	updatedJSON = append(updatedJSON, updatedMetadata[1:len(updatedMetadata)-1]...) // skip { and }
	updatedJSON = append(updatedJSON, jsonData[metadataObjEnd:]...)

	// Replace outputFile with outputFilePath
	if outputFilePath != "" {
		if exportBatchSize <= 0 {
			// Export everything in one file with preserved field order
			if err := os.WriteFile(outputFilePath, updatedJSON, 0644); err != nil {
				return 0, fmt.Errorf("failed to write file %s: %w", outputFilePath, err)
			}
			fmt.Printf("Exported JSON to %s\n", outputFilePath)
		} else {
			// For batch processing, we need to extract data array and create batches
			// This is more complex but still preserves field order in each record
			batches := splitIntoBatches(countingStruct.Data, updatedMetadata, exportBatchSize)
			totalBatches := len(batches)

			for i, batchJSON := range batches {
				var fileName string
				if totalBatches == 1 {
					fileName = outputFilePath
				} else {
					ext := filepath.Ext(outputFilePath)
					base := strings.TrimSuffix(outputFilePath, ext)
					fileName = fmt.Sprintf("%s_%d%s", base, i+1, ext)
				}

				if err := os.WriteFile(fileName, batchJSON, 0644); err != nil {
					return 0, fmt.Errorf("failed to write batch file %s: %w", fileName, err)
				}
				fmt.Printf("Exported batch %d JSON to %s\n", i+1, fileName)
			}
		}
		// Replace outputDir with outputDirPath
	} else if outputDirPath != "" {
		// Process each CVE individually while preserving field order
		if err := exportToDirPreservingOrder(countingStruct.Data, updatedMetadata, outputDirPath); err != nil {
			return 0, err
		}
		fmt.Printf("Exported JSON files to %s\n", outputDirPath)
	}

	return exportedCount, nil
}

// Helper functions

// findMatchingCloseBrace finds the matching closing brace for an opening brace
func findMatchingCloseBrace(data []byte, openPos int) int {
	depth := 1
	for i := openPos + 1; i < len(data); i++ {
		if data[i] == '{' {
			depth++
		} else if data[i] == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1 // No matching brace found
}

// Split data into batches while preserving field order
func splitIntoBatches(data []json.RawMessage, metadata []byte, batchSize int) [][]byte {
	totalBatches := (len(data) + batchSize - 1) / batchSize
	batches := make([][]byte, 0, totalBatches)

	for i := 0; i < totalBatches; i++ {
		start := i * batchSize
		end := start + batchSize
		if end > len(data) {
			end = len(data)
		}

		batchJSON := createBatchJSON(data[start:end], metadata)
		batches = append(batches, batchJSON)
	}

	return batches
}

// Create JSON for a batch with preserved field order
func createBatchJSON(batchData []json.RawMessage, metadata []byte) []byte {
	// Prepare the batch JSON
	result := []byte(`{"metadata":`)
	result = append(result, metadata...)
	result = append(result, []byte(`,"data":[`)...)

	for i, item := range batchData {
		if i > 0 {
			result = append(result, ',')
		}
		result = append(result, item...)
	}

	result = append(result, []byte(`]}`)...)
	return result
}

// Export to directory with preserved field order
func exportToDirPreservingOrder(data []json.RawMessage, metadata []byte, outputDir string) error {
	for _, rawCVE := range data {
		// Extract CVE ID without full decode
		var cveIDStruct struct {
			CVE struct {
				ID string `json:"id"`
			} `json:"cve"`
		}

		if err := json.Unmarshal(rawCVE, &cveIDStruct); err != nil {
			log.Printf("Skipping malformed CVE entry: %v", err)
			continue
		}

		cveID := cveIDStruct.CVE.ID
		if cveID == "" {
			log.Printf("Skipping CVE with missing ID")
			continue
		}

		year := extractYearFromCVE(cveID)
		if year == "" {
			log.Printf("Skipping CVE with invalid ID format: %s", cveID)
			continue
		}

		// Ensure directory exists
		dirPath := filepath.Join(outputDir, year)
		if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Create single CVE JSON with preserved field order
		singleCVEJSON := []byte(`{"metadata":`)
		singleCVEJSON = append(singleCVEJSON, metadata...)
		singleCVEJSON = append(singleCVEJSON, []byte(`,"data":[`)...)
		singleCVEJSON = append(singleCVEJSON, rawCVE...)
		singleCVEJSON = append(singleCVEJSON, []byte(`]}`)...)

		// Write the JSON file for this CVE
		filePath := filepath.Join(dirPath, cveID+".json")
		if err := os.WriteFile(filePath, singleCVEJSON, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file for %s: %w", cveID, err)
		}
	}

	return nil
}

// Extracts year from CVE ID (e.g., CVE-2024-1234 -> "2024")
func extractYearFromCVE(cveID string) string {
	parts := strings.Split(cveID, "-")
	if len(parts) >= 2 {
		return parts[1] // Return year part
	}
	return ""
}
