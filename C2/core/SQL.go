package core

func GetSpecificSQL(table string, column string, selected string, selectedValue string) string {
	var outputData string
	Err = DB.QueryRow("SELECT "+column+"  FROM "+table+" where "+selected+" = ?", selectedValue).Scan(&outputData)
	if Err != nil {
		return " "
	}
	return outputData

}

func countRows(table string) int {
	var val int
	rows := DB.QueryRow("SELECT COUNT(*) as count FROM " + table)
	_ = rows.Scan(&val)
	return val
}
