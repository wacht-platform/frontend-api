package model

type Organization struct {
	Model
	Name     string `json:"name"`
	ImageUrl string `json:"image_url"`
}
