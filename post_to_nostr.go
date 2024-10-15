package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"
)

var (
	photoDir    string
	relays      string
	privateKey  string
	mediaServer string
)

func init() {
	flag.StringVar(&photoDir, "photoDir", "photos", "Directory containing photos and captions")
	flag.StringVar(&relays, "relays", "wss://relay.damus.io,wss://nostr-pub.wellorder.net", "Comma-separated list of Nostr relays")
	flag.StringVar(&privateKey, "privateKey", "", "Your Nostr private key in hex format")
	flag.StringVar(&mediaServer, "mediaServer", "https://nostr.build", "NIP-96 compliant media server URL")
}

// Define UploadedImages and SentEvents types
type UploadedImages map[string]string // map[imagePath]imageURL

type SentEvents map[string]string // map[postID]eventID

func main() {
	flag.Parse()

	if privateKey == "" {
		privateKey = os.Getenv("NOSTR_PRIVATE_KEY")
		if privateKey == "" {
			log.Fatal("Please provide your Nostr private key using the -privateKey flag or NOSTR_PRIVATE_KEY environment variable")
		}
	}

	pubKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}

	// Load uploaded images and sent events
	uploadedImagesFile := "uploaded_images.json"
	uploadedImages, err := loadUploadedImages(uploadedImagesFile)
	if err != nil {
		log.Fatalf("Error loading uploaded images: %v", err)
	}

	sentEventsFile := "sent_events.json"
	sentEvents, err := loadSentEvents(sentEventsFile)
	if err != nil {
		log.Fatalf("Error loading sent events: %v", err)
	}

	relayUrls := strings.Split(relays, ",")

	// Create relay pool
	relayPool := make([]*nostr.Relay, 0)
	ctx := context.Background()
	for _, url := range relayUrls {
		relay, err := nostr.RelayConnect(ctx, strings.TrimSpace(url))
		if err != nil {
			log.Printf("Failed to connect to relay %s: %v", url, err)
			continue
		}
		defer relay.Close()
		relayPool = append(relayPool, relay)
	}

	posts, err := getPosts(photoDir)
	if err != nil {
		log.Fatalf("Error getting posts: %v", err)
	}

	for _, post := range posts {
		postID := post.PostID

		// Check if the event for this post has already been sent
		if eventID, exists := sentEvents[postID]; exists {
			fmt.Printf("Post %s has already been sent with event ID %s. Skipping.\n", postID, eventID)
			continue
		}

		// Upload images and collect URLs
		imageUrls := make([]string, 0)
		for _, imagePath := range post.Images {
			// Check if the image has already been uploaded
			if imageURL, exists := uploadedImages[imagePath]; exists {
				fmt.Printf("Image %s has already been uploaded. Using URL %s.\n", imagePath, imageURL)
				imageUrls = append(imageUrls, imageURL)
				continue
			}

			fmt.Printf("Uploading %s via NIP-96...\n", imagePath)
			imageUrl, err := uploadImageNIP96(imagePath, privateKey, mediaServer)
			if err != nil {
				log.Printf("Failed to upload %s: %v", imagePath, err)
				continue
			}
			imageUrls = append(imageUrls, imageUrl)
			// Save the uploaded image
			uploadedImages[imagePath] = imageUrl
			// Save the uploaded images to file
			err = saveUploadedImages(uploadedImagesFile, uploadedImages)
			if err != nil {
				log.Printf("Failed to save uploaded images: %v", err)
			}

			// Sleep to avoid rate limiting
			time.Sleep(1 * time.Second)
		}

		// Create the content for the main post
		var content string
		if post.Caption != "" {
			content = post.Caption + "\n\n" + strings.Join(imageUrls, "\n")
		} else {
			content = strings.Join(imageUrls, "\n")
		}

		fmt.Printf("Posting content for postID %s:\n%s\n", postID, content)

		// Create and publish the main event
		event := nostr.Event{
			PubKey:    pubKey,
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindTextNote,
			Tags:      nostr.Tags{},
			Content:   content,
		}
		err = event.Sign(privateKey)
		if err != nil {
			log.Printf("Failed to sign event: %v", err)
			continue
		}

		for _, relay := range relayPool {
			err := relay.Publish(ctx, event)
			if err != nil {
				log.Printf("Failed to publish event to relay %s: %v", relay.URL, err)
			} else {
				fmt.Printf("Posted to relay %s: %s\n", relay.URL, event.ID)
			}
		}

		// Save the sent event
		sentEvents[postID] = event.ID
		err = saveSentEvents(sentEventsFile, sentEvents)
		if err != nil {
			log.Printf("Failed to save sent events: %v", err)
		}

		// Sleep to avoid rate limiting
		time.Sleep(1 * time.Second)
	}
}

// Post represents a grouped post with images and a caption
type Post struct {
	PostID  string
	Images  []string
	Caption string
}

// getPosts scans the photo directory and groups images by post ID
func getPosts(photoDir string) ([]Post, error) {
	postsMap := make(map[string]*Post)

	// Regex to extract post ID
	re := regexp.MustCompile(`^(.*?_UTC)`)
	err := filepath.Walk(photoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".jpg") || strings.HasSuffix(info.Name(), ".jpeg") || strings.HasSuffix(info.Name(), ".png")) {
			matches := re.FindStringSubmatch(info.Name())
			if len(matches) > 1 {
				postID := matches[1]
				if postsMap[postID] == nil {
					postsMap[postID] = &Post{PostID: postID}
				}
				postsMap[postID].Images = append(postsMap[postID].Images, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Read captions
	for postID, post := range postsMap {
		captionPath := filepath.Join(photoDir, postID+".txt")
		caption, err := ioutil.ReadFile(captionPath)
		if err == nil {
			post.Caption = strings.TrimSpace(string(caption))
			fmt.Printf("Read caption for postID %s: %s\n", postID, post.Caption)
		} else {
			fmt.Printf("No caption found for postID %s at %s\n", postID, captionPath)
		}
		// Sort images
		sort.Strings(post.Images)
	}

	// Convert map to slice
	posts := make([]Post, 0, len(postsMap))
	for _, post := range postsMap {
		posts = append(posts, *post)
	}

	// Sort posts in chronological order based on PostID
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].PostID < posts[j].PostID
	})

	return posts, nil
}

// Load uploaded images from JSON file
func loadUploadedImages(filename string) (UploadedImages, error) {
	data := UploadedImages{}
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil // Return empty map if file does not exist
		}
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Save uploaded images to JSON file
func saveUploadedImages(filename string, data UploadedImages) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // For readability
	err = encoder.Encode(data)
	if err != nil {
		return err
	}
	return nil
}

// Load sent events from JSON file
func loadSentEvents(filename string) (SentEvents, error) {
	data := SentEvents{}
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil // Return empty map if file does not exist
		}
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Save sent events to JSON file
func saveSentEvents(filename string, data SentEvents) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // For readability
	err = encoder.Encode(data)
	if err != nil {
		return err
	}
	return nil
}

// computeFileHashBase64 computes the SHA-256 hash of the file and returns it base64-encoded
func computeFileHashBase64(fileData []byte) string {
	hash := sha256.Sum256(fileData)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// createNIP98AuthorizationHeader creates and signs a NIP-98 event and returns the Authorization header value
func createNIP98AuthorizationHeader(privateKey, method, url, payload string) (string, error) {
	pubKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %v", err)
	}

	event := nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Now(),
		Kind:      27235,
		Tags: nostr.Tags{
			nostr.Tag{"u", url},
			nostr.Tag{"method", method},
		},
		Content: "",
	}

	if payload != "" {
		event.Tags = append(event.Tags, nostr.Tag{"payload", payload})
	}

	err = event.Sign(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign NIP-98 event: %v", err)
	}

	// Serialize the event as per NIP-98 (JSON)
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to serialize NIP-98 event: %v", err)
	}

	// Base64-encode the serialized event
	authValue := base64.StdEncoding.EncodeToString(eventJSON)

	// Return the 'Authorization' header value
	return fmt.Sprintf("Nostr %s", authValue), nil
}

// getMediaServerAPIURL retrieves the api_url from the media server's nip96.json
func getMediaServerAPIURL(mediaServer string) (string, error) {
	url := fmt.Sprintf("%s/.well-known/nostr/nip96.json", mediaServer)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch nip96.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to fetch nip96.json: status %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		APIURL string `json:"api_url"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("failed to parse nip96.json: %v", err)
	}

	if response.APIURL == "" {
		return "", fmt.Errorf("api_url not found in nip96.json")
	}

	return response.APIURL, nil
}

// uploadImageNIP96 uploads an image via NIP-96 REST API and returns the image URL
func uploadImageNIP96(imagePath, privateKey, mediaServer string) (string, error) {
	// Fetch the api_url from the media server
	apiURL, err := getMediaServerAPIURL(mediaServer)
	if err != nil {
		return "", err
	}

	// Read image file
	imageData, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return "", err
	}

	// Compute the SHA-256 hash and base64-encode it
	hashBase64 := computeFileHashBase64(imageData)

	// Create the NIP-98 Authorization header
	authHeader, err := createNIP98AuthorizationHeader(privateKey, "POST", apiURL, hashBase64)
	if err != nil {
		return "", err
	}

	// Determine MIME type
	mimeType := mime.TypeByExtension(filepath.Ext(imagePath))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Create a buffer to hold the multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add the file field
	part, err := writer.CreateFormFile("file", filepath.Base(imagePath))
	if err != nil {
		return "", err
	}
	_, err = part.Write(imageData)
	if err != nil {
		return "", err
	}

	// Close the multipart writer to set the terminating boundary
	err = writer.Close()
	if err != nil {
		return "", err
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", apiURL, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", authHeader)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("failed to upload image: status %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response struct {
		Status        string                 `json:"status"`
		Message       string                 `json:"message"`
		ProcessingURL string                 `json:"processing_url"`
		NIP94Event    map[string]interface{} `json:"nip94_event"`
	}
	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	if response.Status != "success" {
		return "", fmt.Errorf("upload failed: %s", response.Message)
	}

	// Extract the URL from the nip94_event tags
	var imageURL string
	tags, ok := response.NIP94Event["tags"].([]interface{})
	if !ok {
		return "", fmt.Errorf("invalid nip94_event format")
	}
	for _, tag := range tags {
		tagArray, ok := tag.([]interface{})
		if !ok || len(tagArray) < 2 {
			continue
		}
		if tagArray[0] == "url" {
			imageURL, _ = tagArray[1].(string)
			break
		}
	}

	if imageURL == "" {
		return "", fmt.Errorf("image URL not found in response")
	}

	return imageURL, nil
}
