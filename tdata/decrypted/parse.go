package decrypted

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/pkg/errors"

	"github.com/atilaromero/telegram-desktop-decrypt/qt"
	"github.com/lunixbochs/struc"
)

func unpack(r io.Reader, data interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error unpacking: %v", r)
		}
	}()
	return struc.Unpack(r, data)
}

func ParseCache(data []byte, keytype uint32) (interface{}, error) {
	r := bytes.NewReader(data)
	switch LSK[keytype].(type) {
	case Audios:
		result := Audios{}
		err := unpack(r, &result)
		return result, errors.Wrap(err, "error parsing cache file")
	case StickerImages:
		result := StickerImages{}
		err := unpack(r, &result)
		return result, errors.Wrap(err, "error parsing cache file")
	case Images:
		result := Images{}
		err := unpack(r, &result)
		return result, errors.Wrap(err, "error parsing cache file")
	case Locations:
		result := Locations{}
		err := binary.Read(r, binary.LittleEndian, &result.FullLen)
		if err != nil {
			return result, errors.Wrap(err, "error parsing cache file")
		}
		for {
			location := Location{}
			err := parseField(r, reflect.Indirect(reflect.ValueOf(&location)))
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				break
			}
			if err != nil {
				return result, errors.Wrap(err, "error parsing cache file")
			}
			if location.MediaKey.LocationType == 0 &&
				location.MediaKey.DC == 0 &&
				location.MediaKey.ID == 0 &&
				len(location.Filename) == 0 &&
				location.Size == 0 {
				//endmark
				break
			}
			result.Locations = append(result.Locations, location)
		}
		return result, nil
	case ReportSpamStatuses:
		result := ReportSpamStatuses{}
		err := unpack(r, &result)
		return result, errors.Wrap(err, "error parsing cache file")
	case UserSettings:
		result := UserSettings{}
		err := binary.Read(r, binary.LittleEndian, &result.FullLen)
		if err != nil {
			return result, errors.Wrap(err, "error parsing cache file")
		}
		r = bytes.NewReader(data[4:result.FullLen])
		result.Settings = make([]map[string]interface{}, 0)
		var blockID uint32
		for {
			err := unpack(r, &blockID)
			if err == io.EOF {
				break
			}
			if err != nil {
				return result, errors.Wrap(err, "error parsing cache file")
			}
			setting, err := parseUserSetting(r, blockID)
			if err != nil {
				return result, errors.Wrap(err, "error parsing cache file")
			}
			result.Settings = append(result.Settings, setting)
		}
		return result, nil
	default:
		return struct{}{}, nil
	}
}

type connectionType struct {
	// This is partially parsed and works only for specific case.
}

func parseConnectionType(r *bytes.Reader) (*connectionType, error) {
	var connType int32
	if err := unpack(r, &connType); err != nil {
		return nil, err
	}

	const (
		dbictAuto           = 0
		dbictHttpAuto       = 1 // not used
		dbictHttpProxy      = 2
		dbictTcpProxy       = 3
		dbictProxiesListOld = 4
		dbictProxiesList    = 5
	)

	switch connType {
	case dbictProxiesList:
		var header struct {
			Count    int32
			Index    int32
			Settings int32
			Calls    int32
		}
		if err := unpack(r, &header); err != nil {
			return nil, err
		}
		if header.Count > 0 {
			return nil, errors.New("not implemented")
		}
		switch header.Settings {
		case 0, 2:
			// System or Disabled.
		case 1:
			// Enabled.
			return nil, errors.New("not implemented")
		}
		return &connectionType{}, nil
	}

	return nil, nil
}

func parseUserSetting(r *bytes.Reader, blockID uint32) (map[string]interface{}, error) {
	userSetting := UserSetting{}
	result := make(map[string]interface{})
	fieldName, ok := DBI[blockID]
	if !ok {
		return nil, fmt.Errorf("blockID not found: 0x%x", blockID)
	}

	// Special case parsers.
	switch fieldName {
	case "DbiConnectionType":
		v, err := parseConnectionType(r)
		if err != nil {
			return nil, fmt.Errorf("failed to parse connection type: %w", err)
		}
		result[fieldName] = v
		return result, nil
	}

	field := reflect.ValueOf(&userSetting).Elem().FieldByName(fieldName)
	if err := parseField(r, field); err != nil {
		return nil, fmt.Errorf("error: %v: %v", fieldName, err)
	}
	result[fieldName] = field.Interface()
	return result, nil
}

func parseField(r *bytes.Reader, field reflect.Value) error {
	switch field.Kind() {
	case reflect.Struct:
		switch field.Interface().(type) {
		case time.Time:
			d := struct {
				Date uint64
				Time uint32
				X    [1]byte
			}{}
			err := unpack(r, &d)
			if err != nil {
				return err
			}
			v := qt.QDateTime(d.Date, d.Time)
			field.Set(reflect.ValueOf(v))
			return nil
		default:
			for i := 0; i < field.NumField(); i++ {
				parseField(r, field.Field(i))
			}
		}
	case reflect.Slice:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			len := int32(0)
			err := unpack(r, &len)
			if err != nil {
				return err
			}
			if len < 0 {
				field.SetBytes([]byte{})
				return nil
			}
			b := make([]byte, len)
			err = unpack(r, b)
			if err != nil {
				return err
			}
			field.SetBytes(b)
		default:
			len := int32(0)
			err := unpack(r, &len)
			if err != nil {
				return err
			}
			slice := reflect.MakeSlice(field.Type(), int(len), int(len))
			for i := 0; i < int(len); i++ {
				parseField(r, slice.Index(i))
			}
			field.Set(slice)
			return nil
		}
	case reflect.String:
		len := int32(0)
		err := unpack(r, &len)
		if err != nil {
			return err
		}
		if len < 0 {
			field.SetString("")
			return nil
		}
		b := make([]byte, len)
		err = unpack(r, b)
		if err != nil {
			return err
		}
		field.SetString(qt.ConvertUtf16(b))
		return nil
	default:
		interf := field.Addr().Interface()
		return unpack(r, interf)
	}
	return nil
}
