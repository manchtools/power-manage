package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/typepb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
)

func TestGuard_CRUDRequestBoundaryCasesCoverEveryRegisteredField(t *testing.T) {
	domains := managementDomains(nil)
	cases, err := generateCRUDBoundaryCases(domains)
	if err != nil {
		t.Fatalf("generate CRUD boundary cases: %v", err)
	}
	cases = guardtest.Discover(t, "registered CRUD request fields", 11, func() ([]crudBoundaryCase, error) {
		return cases, nil
	})

	for _, boundary := range cases {
		t.Run(boundary.name(), func(t *testing.T) {
			if err := protovalidate.Validate(boundary.correct); err != nil {
				t.Fatalf("correct case rejected: %v", err)
			}
			if err := validateCRUDRequest(boundary.correct, boundary.requestMessage); err != nil {
				t.Fatalf("kernel rejected correct case: %v", err)
			}
			if boundary.absent.ProtoReflect().Has(boundary.field) {
				t.Fatal("absent case still has the target field")
			}
			if err := protovalidate.Validate(boundary.wrong); err == nil {
				t.Fatal("wrong case unexpectedly satisfies its validate tag")
			} else if !strings.Contains(err.Error(), string(boundary.field.Name())) {
				t.Fatalf(
					"wrong case error = %v; want failure naming field %s",
					err,
					boundary.field.Name(),
				)
			}
			if err := validateCRUDRequest(boundary.wrong, boundary.requestMessage); err == nil {
				t.Fatal("kernel accepted wrong case")
			} else if !strings.Contains(err.Error(), string(boundary.field.Name())) {
				t.Fatalf(
					"kernel error = %v; want failure naming field %s",
					err,
					boundary.field.Name(),
				)
			}
			if proto.Equal(boundary.correct, boundary.wrong) {
				t.Fatal("correct and wrong cases are identical")
			}
		})
	}
}

func TestCRUDBoundaryGenerator_FailsClosed(t *testing.T) {
	tests := map[string]struct {
		mutate func(crudDomain) crudDomain
		want   string
	}{
		"zero fields": {
			mutate: func(domain crudDomain) crudDomain {
				for operation := crudCreate; operation <= crudDelete; operation++ {
					domain.requestMessages[operation] = (&emptypb.Empty{}).
						ProtoReflect().Descriptor().FullName()
				}
				return domain
			},
			want: "zero request fields",
		},
		"missing validate rule": {
			mutate: func(domain crudDomain) crudDomain {
				domain.requestMessages[crudGet] = (&typepb.Type{}).
					ProtoReflect().Descriptor().FullName()
				return domain
			},
			want: "no validation rules",
		},
		"unsupported rule kind": {
			mutate: func(domain crudDomain) crudDomain {
				domain.requestMessages[crudGet] = (&powermanagev1.ArtifactChunk{}).
					ProtoReflect().Descriptor().FullName()
				return domain
			},
			want: "unsupported",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			valid := managementDomains(nil)[0]
			valid.requestMessages = cloneRequestMessages(valid.requestMessages)
			_, err := generateCRUDBoundaryCases([]crudDomain{test.mutate(valid)})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("generator error = %v; want category containing %q", err, test.want)
			}
		})
	}
}

func TestGeneratedWrongCasesStopBeforeAuthorizationAndWork(t *testing.T) {
	domains := managementDomains(nil)
	boundaries, err := generateCRUDBoundaryCases(domains)
	if err != nil {
		t.Fatalf("generate CRUD boundary cases: %v", err)
	}
	resolver := &kernelTestResolver{
		access: authz.EffectiveAccess{
			Permissions: map[authz.Permission]authz.Reach{
				"devices.manage": {Global: true},
			},
		},
	}
	gate, err := auth.NewAuthorizationGate(resolver)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	appender := &kernelTestStore{}
	kernel, err := newCRUDKernel(appender, gate, domains)
	if err != nil {
		t.Fatalf("create CRUD kernel: %v", err)
	}
	for _, boundary := range boundaries {
		err := invokeWrongBoundaryCase(t.Context(), kernel, boundary)
		if connectCode := connect.CodeOf(err); connectCode != connect.CodeInvalidArgument {
			t.Fatalf("%s wrong-case code = %v; want InvalidArgument", boundary.name(), connectCode)
		}
	}
	if resolver.calls != 0 || appender.appends != 0 {
		t.Fatalf(
			"generated wrong-case effects = resolver %d, appends %d; want zero",
			resolver.calls,
			appender.appends,
		)
	}
}

func invokeWrongBoundaryCase(
	ctx context.Context,
	kernel *CRUDKernel,
	boundary crudBoundaryCase,
) error {
	switch boundary.operation {
	case crudCreate:
		_, err := kernel.create(ctx, boundary.procedure, boundary.domain, boundary.wrong)
		return err
	case crudGet:
		_, err := kernel.get(ctx, boundary.procedure, boundary.domain, boundary.wrong)
		return err
	case crudList:
		_, err := kernel.list(ctx, boundary.procedure, boundary.domain, boundary.wrong)
		return err
	case crudUpdate:
		_, err := kernel.update(ctx, boundary.procedure, boundary.domain, boundary.wrong)
		return err
	case crudDelete:
		_, err := kernel.delete(ctx, boundary.procedure, boundary.domain, boundary.wrong)
		return err
	default:
		return errors.New("crud boundary generator: unknown operation")
	}
}

type crudBoundaryCase struct {
	domain         string
	operation      crudOperation
	procedure      string
	requestMessage protoreflect.FullName
	field          protoreflect.FieldDescriptor
	correct        proto.Message
	absent         proto.Message
	wrong          proto.Message
}

func (c crudBoundaryCase) name() string {
	return fmt.Sprintf("%s/%d/%s", c.domain, c.operation, c.field.Name())
}

func generateCRUDBoundaryCases(domains []crudDomain) ([]crudBoundaryCase, error) {
	if len(domains) == 0 {
		return nil, errors.New("crud boundary generator: zero registered domains")
	}
	var cases []crudBoundaryCase
	for _, domain := range domains {
		domainFields := 0
		for operation := crudCreate; operation <= crudDelete; operation++ {
			messageName, registered := domain.requestMessages[operation]
			if !registered {
				continue
			}
			messageType, err := protoregistry.GlobalTypes.FindMessageByName(messageName)
			if err != nil {
				return nil, fmt.Errorf(
					"crud boundary generator: domain %q operation %d request %q: %w",
					domain.name,
					operation,
					messageName,
					err,
				)
			}
			descriptor := messageType.Descriptor()
			fields := descriptor.Fields()
			domainFields += fields.Len()
			for index := 0; index < fields.Len(); index++ {
				field := fields.Get(index)
				correct := dynamicpb.NewMessage(descriptor)
				for fillIndex := 0; fillIndex < fields.Len(); fillIndex++ {
					fill := fields.Get(fillIndex)
					value, _, err := crudBoundaryValues(fill)
					if err != nil {
						return nil, err
					}
					setCRUDBoundaryField(correct, fill, value)
				}
				absent := proto.Clone(correct)
				absent.ProtoReflect().Clear(field)
				wrong := proto.Clone(correct)
				_, wrongValue, err := crudBoundaryValues(field)
				if err != nil {
					return nil, err
				}
				setCRUDBoundaryField(wrong.ProtoReflect(), field, wrongValue)
				cases = append(cases, crudBoundaryCase{
					domain:         domain.name,
					operation:      operation,
					procedure:      domain.procedures[operation],
					requestMessage: messageName,
					field:          field,
					correct:        correct,
					absent:         absent,
					wrong:          wrong,
				})
			}
		}
		if domainFields == 0 {
			return nil, fmt.Errorf(
				"crud boundary generator: domain %q has zero request fields",
				domain.name,
			)
		}
	}
	return cases, nil
}

func setCRUDBoundaryField(
	message protoreflect.Message,
	field protoreflect.FieldDescriptor,
	value protoreflect.Value,
) {
	if !field.IsList() {
		message.Set(field, value)
		return
	}
	source := value.List()
	target := message.Mutable(field).List()
	target.Truncate(0)
	for index := 0; index < source.Len(); index++ {
		target.Append(source.Get(index))
	}
}

func crudBoundaryValues(
	field protoreflect.FieldDescriptor,
) (protoreflect.Value, protoreflect.Value, error) {
	rules, _ := proto.GetExtension(field.Options(), validate.E_Field).(*validate.FieldRules)
	if rules == nil {
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has no validation rules",
			field.FullName(),
		)
	}
	return crudBoundaryValuesWithRules(field, rules)
}

func crudBoundaryValuesWithRules(
	field protoreflect.FieldDescriptor,
	rules *validate.FieldRules,
) (protoreflect.Value, protoreflect.Value, error) {
	if field.IsList() {
		return crudRepeatedBoundaryValues(field, rules.GetRepeated())
	}
	if field.Kind() == protoreflect.MessageKind {
		return crudMessageBoundaryValues(field, rules)
	}
	return crudScalarBoundaryValues(field, rules)
}

func crudScalarBoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.FieldRules,
) (protoreflect.Value, protoreflect.Value, error) {
	if rules.GetType() == nil {
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-scalar",
			field.FullName(),
		)
	}
	switch field.Kind() {
	case protoreflect.StringKind:
		correct, wrong, err := crudStringBoundaryValues(field, rules.GetString())
		return protoreflect.ValueOfString(correct), protoreflect.ValueOfString(wrong), err
	case protoreflect.Uint32Kind:
		correct, wrong, err := crudUint32BoundaryValues(field, rules.GetUint32())
		return protoreflect.ValueOfUint32(correct), protoreflect.ValueOfUint32(wrong), err
	case protoreflect.Uint64Kind:
		correct, wrong, err := crudUint64BoundaryValues(field, rules.GetUint64())
		return protoreflect.ValueOfUint64(correct), protoreflect.ValueOfUint64(wrong), err
	case protoreflect.EnumKind:
		correct, wrong, err := crudEnumBoundaryValues(field, rules.GetEnum())
		return protoreflect.ValueOfEnum(correct), protoreflect.ValueOfEnum(wrong), err
	default:
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: %s field kind",
			field.FullName(),
			field.Kind(),
		)
	}
}

func crudRepeatedBoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.RepeatedRules,
) (protoreflect.Value, protoreflect.Value, error) {
	if rules == nil {
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-repeated",
			field.FullName(),
		)
	}
	if !rules.HasMinItems() && !rules.HasMaxItems() && !rules.HasUnique() {
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: repeated has no wrong case",
			field.FullName(),
		)
	}
	correctCount := rules.GetMinItems()
	var item protoreflect.Value
	var err error
	if correctCount > 0 || rules.GetUnique() || rules.HasMaxItems() {
		if rules.GetItems() == nil {
			return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
				"crud boundary generator: field %s has unsupported rules: repeated items",
				field.FullName(),
			)
		}
		item, _, err = crudScalarBoundaryValues(field, rules.GetItems())
		if err != nil {
			return protoreflect.Value{}, protoreflect.Value{}, err
		}
	}
	correctItems := make([]protoreflect.Value, correctCount)
	for index := range correctItems {
		correctItems[index] = item
	}
	correct := crudListValue(field, correctItems)

	switch {
	case rules.HasMinItems() && rules.GetMinItems() > 0:
		return correct, crudListValue(field, nil), nil
	case rules.GetUnique():
		return correct, crudListValue(field, []protoreflect.Value{item, item}), nil
	case rules.HasMaxItems() && rules.GetMaxItems() < uint64(math.MaxInt):
		wrongItems := make([]protoreflect.Value, int(rules.GetMaxItems()+1))
		for index := range wrongItems {
			wrongItems[index] = item
		}
		return correct, crudListValue(field, wrongItems), nil
	default:
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: repeated bounds",
			field.FullName(),
		)
	}
}

func crudListValue(
	field protoreflect.FieldDescriptor,
	items []protoreflect.Value,
) protoreflect.Value {
	holder := dynamicpb.NewMessage(field.ContainingMessage())
	list := holder.Mutable(field).List()
	for _, item := range items {
		list.Append(item)
	}
	return holder.Get(field)
}

func crudMessageBoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.FieldRules,
) (protoreflect.Value, protoreflect.Value, error) {
	if !rules.GetRequired() {
		return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: optional message",
			field.FullName(),
		)
	}
	if member := firstRequiredMessageOneofMember(field.Message()); member != nil {
		correct := dynamicpb.NewMessage(field.Message())
		correct.Set(
			member,
			protoreflect.ValueOfMessage(dynamicpb.NewMessage(member.Message())),
		)
		wrong := dynamicpb.NewMessage(field.Message())
		return protoreflect.ValueOfMessage(correct), protoreflect.ValueOfMessage(wrong), nil
	}
	if field.Message().FullName() == "google.protobuf.Timestamp" {
		seconds := field.Message().Fields().ByName("seconds")
		if seconds == nil {
			return protoreflect.Value{}, protoreflect.Value{}, fmt.Errorf(
				"crud boundary generator: field %s has an invalid timestamp descriptor",
				field.FullName(),
			)
		}
		correct := dynamicpb.NewMessage(field.Message())
		correct.Set(seconds, protoreflect.ValueOfInt64(253_402_300_799))
		wrong := dynamicpb.NewMessage(field.Message())
		wrong.Set(seconds, protoreflect.ValueOfInt64(0))
		return protoreflect.ValueOfMessage(correct), protoreflect.ValueOfMessage(wrong), nil
	}
	correct := dynamicpb.NewMessage(field.Message())
	fields := field.Message().Fields()
	for index := 0; index < fields.Len(); index++ {
		nested := fields.Get(index)
		value, _, err := crudBoundaryValues(nested)
		if err != nil {
			return protoreflect.Value{}, protoreflect.Value{}, err
		}
		setCRUDBoundaryField(correct, nested, value)
	}
	wrong := dynamicpb.NewMessage(field.Message())
	return protoreflect.ValueOfMessage(correct), protoreflect.ValueOfMessage(wrong), nil
}

func firstRequiredMessageOneofMember(
	message protoreflect.MessageDescriptor,
) protoreflect.FieldDescriptor {
	oneofs := message.Oneofs()
	for index := 0; index < oneofs.Len(); index++ {
		oneof := oneofs.Get(index)
		rules, _ := proto.GetExtension(
			oneof.Options(),
			validate.E_Oneof,
		).(*validate.OneofRules)
		if rules == nil || !rules.GetRequired() || oneof.Fields().Len() == 0 {
			continue
		}
		member := oneof.Fields().Get(0)
		if member.Kind() == protoreflect.MessageKind {
			return member
		}
	}
	return nil
}

func crudEnumBoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.EnumRules,
) (protoreflect.EnumNumber, protoreflect.EnumNumber, error) {
	if rules == nil {
		return 0, 0, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-enum",
			field.FullName(),
		)
	}
	if rules.Const != nil {
		correct := protoreflect.EnumNumber(rules.GetConst())
		return correct, correct + 1, nil
	}
	if len(rules.GetIn()) > 0 {
		correct := protoreflect.EnumNumber(rules.GetIn()[0])
		wrong := protoreflect.EnumNumber(0)
		for slices.Contains(rules.GetIn(), int32(wrong)) {
			wrong++
		}
		return correct, wrong, nil
	}
	if len(rules.GetNotIn()) > 0 {
		wrong := protoreflect.EnumNumber(rules.GetNotIn()[0])
		values := field.Enum().Values()
		for index := 0; index < values.Len(); index++ {
			correct := values.Get(index).Number()
			if !slices.Contains(rules.GetNotIn(), int32(correct)) {
				return correct, wrong, nil
			}
		}
	}
	if rules.GetDefinedOnly() {
		values := field.Enum().Values()
		if values.Len() == 0 {
			return 0, 0, fmt.Errorf(
				"crud boundary generator: field %s has no defined enum values",
				field.FullName(),
			)
		}
		correct := values.Get(0).Number()
		maximum := correct
		for index := 1; index < values.Len(); index++ {
			maximum = max(maximum, values.Get(index).Number())
		}
		if maximum == protoreflect.EnumNumber(math.MaxInt32) {
			return 0, 0, fmt.Errorf(
				"crud boundary generator: field %s cannot derive an undefined enum value",
				field.FullName(),
			)
		}
		wrong := maximum + 1
		return correct, wrong, nil
	}
	return 0, 0, fmt.Errorf(
		"crud boundary generator: field %s has unsupported rules: enum has no wrong case",
		field.FullName(),
	)
}

func crudStringBoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.StringRules,
) (string, string, error) {
	if rules == nil {
		return "", "", fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-string",
			field.FullName(),
		)
	}
	ulid, _ := proto.GetExtension(rules, powermanagev1.E_Ulid).(bool)
	if ulid {
		return "01J00000000000000000000090", "not-a-ulid", nil
	}
	if rules.HasPattern() {
		var correct, wrong string
		switch rules.GetPattern() {
		case "^[0-7][0-9A-HJKMNP-TV-Z]{25}$":
			correct, wrong = "01J00000000000000000000090", "not-a-ulid"
		case "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$":
			correct, wrong = "users.manage", "not a permission"
		case "^[a-z][a-z0-9-]*$":
			correct, wrong = "corporate", "not a slug"
		default:
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s has unsupported rules: string pattern",
				field.FullName(),
			)
		}
		if rules.HasConst() || rules.HasLen() || rules.HasLenBytes() ||
			rules.HasPrefix() || rules.HasSuffix() ||
			rules.HasContains() || rules.HasWellKnown() ||
			len(rules.GetIn()) > 0 || len(rules.GetNotIn()) > 0 {
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s has unsupported rules: compound string pattern",
				field.FullName(),
			)
		}
		if !crudStringLengthRulesAllow(rules, correct) {
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s pattern candidate violates length rules",
				field.FullName(),
			)
		}
		return correct, wrong, nil
	}
	if rules.HasPrefix() || rules.HasSuffix() ||
		rules.HasContains() || rules.HasWellKnown() ||
		len(rules.GetIn()) > 0 || len(rules.GetNotIn()) > 0 {
		return "", "", fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: compound string",
			field.FullName(),
		)
	}
	var correct string
	switch {
	case rules.HasConst():
		correct = rules.GetConst()
	case rules.HasLen():
		correct = strings.Repeat("x", int(rules.GetLen()))
	case rules.HasLenBytes():
		correct = strings.Repeat("x", int(rules.GetLenBytes()))
	default:
		length := uint64(1)
		if rules.HasMinLen() && rules.GetMinLen() > length {
			length = rules.GetMinLen()
		}
		if rules.HasMinBytes() && rules.GetMinBytes() > length {
			length = rules.GetMinBytes()
		}
		if length > uint64(math.MaxInt) {
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s length is unsupported",
				field.FullName(),
			)
		}
		correct = strings.Repeat("x", int(length))
	}
	var wrong string
	switch {
	case rules.HasMaxLen():
		if rules.GetMaxLen() >= uint64(math.MaxInt) {
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s max_len is unsupported",
				field.FullName(),
			)
		}
		wrong = strings.Repeat("x", int(rules.GetMaxLen()+1))
	case rules.HasMaxBytes():
		if rules.GetMaxBytes() >= uint64(math.MaxInt) {
			return "", "", fmt.Errorf(
				"crud boundary generator: field %s max_bytes is unsupported",
				field.FullName(),
			)
		}
		wrong = strings.Repeat("x", int(rules.GetMaxBytes()+1))
	case rules.HasLen():
		wrong = correct + "x"
	case rules.HasLenBytes():
		wrong = correct + "x"
	case rules.HasMinLen() && rules.GetMinLen() > 0:
		wrong = strings.Repeat("x", int(rules.GetMinLen()-1))
	case rules.HasMinBytes() && rules.GetMinBytes() > 0:
		wrong = strings.Repeat("x", int(rules.GetMinBytes()-1))
	case rules.HasConst():
		wrong = correct + "x"
	default:
		return "", "", fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: string has no wrong case",
			field.FullName(),
		)
	}
	return correct, wrong, nil
}

func crudStringLengthRulesAllow(rules *validate.StringRules, value string) bool {
	runes := uint64(utf8.RuneCountInString(value))
	bytes := uint64(len(value))
	return (!rules.HasMinLen() || runes >= rules.GetMinLen()) &&
		(!rules.HasMaxLen() || runes <= rules.GetMaxLen()) &&
		(!rules.HasMinBytes() || bytes >= rules.GetMinBytes()) &&
		(!rules.HasMaxBytes() || bytes <= rules.GetMaxBytes())
}

func crudUint32BoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.UInt32Rules,
) (uint32, uint32, error) {
	if rules == nil {
		return 0, 0, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-uint32",
			field.FullName(),
		)
	}
	var correct uint32 = 1
	switch {
	case rules.HasConst():
		correct = rules.GetConst()
	case rules.HasGte():
		correct = rules.GetGte()
	case rules.HasGt() && rules.GetGt() < math.MaxUint32:
		correct = rules.GetGt() + 1
	}
	switch {
	case rules.HasLte() && rules.GetLte() < math.MaxUint32:
		return correct, rules.GetLte() + 1, nil
	case rules.HasLt():
		return correct, rules.GetLt(), nil
	case rules.HasGte() && rules.GetGte() > 0:
		return correct, rules.GetGte() - 1, nil
	case rules.HasGt():
		return correct, rules.GetGt(), nil
	case rules.HasConst():
		return correct, correct + 1, nil
	default:
		return 0, 0, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: uint32",
			field.FullName(),
		)
	}
}

func crudUint64BoundaryValues(
	field protoreflect.FieldDescriptor,
	rules *validate.UInt64Rules,
) (uint64, uint64, error) {
	if rules == nil {
		return 0, 0, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: non-uint64",
			field.FullName(),
		)
	}
	var correct uint64 = 1
	switch {
	case rules.HasConst():
		correct = rules.GetConst()
	case rules.HasGte():
		correct = rules.GetGte()
	case rules.HasGt() && rules.GetGt() < math.MaxUint64:
		correct = rules.GetGt() + 1
	}
	switch {
	case rules.HasLte() && rules.GetLte() < math.MaxUint64:
		return correct, rules.GetLte() + 1, nil
	case rules.HasLt():
		return correct, rules.GetLt(), nil
	case rules.HasGte() && rules.GetGte() > 0:
		return correct, rules.GetGte() - 1, nil
	case rules.HasGt():
		return correct, rules.GetGt(), nil
	case rules.HasConst() && correct < math.MaxUint64:
		return correct, correct + 1, nil
	default:
		return 0, 0, fmt.Errorf(
			"crud boundary generator: field %s has unsupported rules: uint64",
			field.FullName(),
		)
	}
}
