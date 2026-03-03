package status

func CalculateStatus(qty, threshold int) string {
	if qty <= 0 {
		return "No Stock"
	} else if qty <= threshold {
		return "Low Stock"
	}
	return "In Stock"
}
