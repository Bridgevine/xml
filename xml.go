package xml

import (
	"bytes"
	"encoding/xml"
	"io"
	"reflect"
)

// Errors that can be thrown.
var (
	ErrMissingTypesInfo = xml.UnmarshalError("The type information has not been specified.")
)

// UnmarshalElement handles the unmarshalling of the details
// according to the specified types information.
func UnmarshalElement(details []byte, typesInfo interface{}) ([]interface{}, error) {
	if typesInfo == nil {
		return nil, ErrMissingTypesInfo
	}

	mt, mtOK := typesInfo.(map[string]reflect.Type)
	mp, mpOK := typesInfo.(map[string]interface{})

	usingPtr := reflect.TypeOf(typesInfo).Kind() == reflect.Ptr
	usingMT := mtOK && len(mt) > 0
	usingMP := mpOK && len(mp) > 0

	// Checking if the type information was passed
	// using one of the three supported approaches.
	if !(usingPtr || usingMP || usingMT) {
		return nil, ErrMissingTypesInfo
	}

	var results []interface{}

	dec := xml.NewDecoder(bytes.NewReader(details))

	for {
		// Get the next token to be processed.
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return results, nil
			}
			return nil, err
		}

		if tok == nil {
			return results, nil
		}

		switch se := tok.(type) {
		case xml.StartElement:
			if usingPtr {
				if err := dec.DecodeElement(typesInfo, &se); err != nil {
					return nil, err
				}
				results = append(results, typesInfo)
				continue
			}

			if usingMP {
				if ptr, ok := mp[se.Name.Local]; ok {
					if reflect.TypeOf(ptr).Kind() != reflect.Ptr {
						return nil, xml.UnmarshalError("non-pointer passed to unmarshal element " + se.Name.Local)
					}
					if err := dec.DecodeElement(ptr, &se); err != nil {
						return nil, err
					}
					results = append(results, ptr)
				}
				continue
			}

			if usingMT {
				if typ, ok := mt[se.Name.Local]; ok {
					ptr := reflect.New(typ).Interface()
					if err := dec.DecodeElement(ptr, &se); err != nil {
						return nil, err
					}
					results = append(results, ptr)
				}
				continue
			}
		}
	}
}
