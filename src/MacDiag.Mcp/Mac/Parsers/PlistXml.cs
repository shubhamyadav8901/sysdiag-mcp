using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace MacDiag.Mcp.Mac.Parsers;

public abstract record PlistValue;

public sealed record PlistString(string Value) : PlistValue;

public sealed record PlistBool(bool Value) : PlistValue;

public sealed record PlistInteger(long Value) : PlistValue;

public sealed record PlistArray(IReadOnlyList<PlistValue> Items) : PlistValue;

public sealed record PlistDict(PlistDictionary Value) : PlistValue;

/// <summary>A date, data or real: kept as text, because nothing here needs it as a number.</summary>
public sealed record PlistOther(string Kind, string Text) : PlistValue;

/// <summary>A plist dictionary with typed lookups that answer null for a missing key or another type.</summary>
public sealed class PlistDictionary(IReadOnlyDictionary<string, PlistValue> values) : IReadOnlyDictionary<string, PlistValue>
{
    public PlistValue this[string key] => values[key];

    public IEnumerable<string> Keys => values.Keys;

    public IEnumerable<PlistValue> Values => values.Values;

    public int Count => values.Count;

    public bool ContainsKey(string key) => values.ContainsKey(key);

    public bool TryGetValue(string key, out PlistValue value) => values.TryGetValue(key, out value!);

    public IEnumerator<KeyValuePair<string, PlistValue>> GetEnumerator() => values.GetEnumerator();

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

    public string? String(string key) => values.GetValueOrDefault(key) is PlistString s ? s.Value : null;

    public bool? Bool(string key) => values.GetValueOrDefault(key) is PlistBool b ? b.Value : null;

    public long? Integer(string key) => values.GetValueOrDefault(key) is PlistInteger i ? i.Value : null;

    public PlistDictionary? Dict(string key) => values.GetValueOrDefault(key) is PlistDict d ? d.Value : null;

    public IReadOnlyList<string> Strings(string key) =>
        values.GetValueOrDefault(key) is PlistArray a ? a.Items.OfType<PlistString>().Select(s => s.Value).ToList() : [];
}

/// <summary>Apple's XML property list, as plutil -convert xml1 -o - prints it.</summary>
/// <remarks>
/// Read with DTD processing ignored and no resolver, so the DOCTYPE line every plist carries is accepted but
/// nothing it names is fetched, and an entity it does not declare is an error rather than an expansion.
/// </remarks>
public static class PlistXml
{
    public static PlistDictionary Parse(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);

        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader(xml.TrimStart()), settings);
        var document = XDocument.Load(reader);
        var root = document.Root?.Elements("dict").FirstOrDefault()
                   ?? throw new XmlException("The property list has no top-level dictionary.");
        return Dict(root);
    }

    private static PlistDictionary Dict(XElement dict)
    {
        var values = new Dictionary<string, PlistValue>(StringComparer.Ordinal);
        var children = dict.Elements().ToList();
        for (var i = 0; i + 1 < children.Count; i += 2)
        {
            if (children[i].Name.LocalName == "key")
            {
                values[children[i].Value] = Value(children[i + 1]);
            }
        }

        return new PlistDictionary(values);
    }

    private static PlistValue Value(XElement element) => element.Name.LocalName switch
    {
        "string" => new PlistString(element.Value),
        "true" => new PlistBool(true),
        "false" => new PlistBool(false),
        "integer" when long.TryParse(element.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number) => new PlistInteger(number),
        "array" => new PlistArray(element.Elements().Select(Value).ToList()),
        "dict" => new PlistDict(Dict(element)),
        var kind => new PlistOther(kind, element.Value),
    };
}
