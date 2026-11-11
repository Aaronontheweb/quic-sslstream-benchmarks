#nullable enable
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length != 2 || args[1] is not ("classic" or "runtime"))
    throw new ArgumentException("Supply an assembly and expected application async mode: classic or runtime.");

using var input = File.OpenRead(args[0]);
using var pe = new PEReader(input);
var metadata = pe.GetMetadataReader();
var required = new[] { "RunAsync", "SendData", "ReadAcks", "ReadData", "WriteAcks", "WriteNumber", "ExpectNumber" };
var methods = new List<object>();
var seen = new HashSet<string>();
var runtimeCount = 0;
var expectedRuntime = args[1] == "runtime";

foreach (var handle in metadata.MethodDefinitions)
{
    var method = metadata.GetMethodDefinition(handle);
    var name = metadata.GetString(method.Name);
    var type = metadata.GetTypeDefinition(method.GetDeclaringType());
    var owner = metadata.GetString(type.Name);
    var guard = name.StartsWith("<RunAsync>g__Guard", StringComparison.Ordinal);
    var selected = guard || owner == "Protocol" && required.Contains(name);
    var runtime = ((int)method.ImplAttributes & 0x2000) != 0;
    if (runtime)
        runtimeCount++;
    if (!selected)
        continue;

    var compilerStateMachine = false;
    foreach (var attributeHandle in method.GetCustomAttributes())
    {
        var attribute = metadata.GetCustomAttribute(attributeHandle);
        if (attribute.Constructor.Kind != HandleKind.MemberReference)
            continue;
        var constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (constructor.Parent.Kind == HandleKind.TypeReference)
        {
            var attributeType = metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent);
            compilerStateMachine |= metadata.GetString(attributeType.Name) == "AsyncStateMachineAttribute";
        }
    }
    var key = guard ? "Guard" : name;
    if (!seen.Add(key) || runtime != expectedRuntime || compilerStateMachine == expectedRuntime)
        throw new InvalidDataException($"Unexpected or duplicate lowering for {owner}.{name}.");
    methods.Add(new { owner, name, implementationFlags = (int)method.ImplAttributes, runtimeAsync = runtime, compilerStateMachine });
}

if (!required.All(seen.Contains) || !seen.Contains("Guard") || expectedRuntime && runtimeCount == 0 || !expectedRuntime && runtimeCount != 0)
    throw new InvalidDataException("Required workload methods or application async-mode proof are missing.");

Console.WriteLine(JsonSerializer.Serialize(new { applicationAsyncMode = args[1], runtimeAsyncMethodCount = runtimeCount, methods }));
