using System.Globalization;
using System.Windows;

namespace HiddifyGuard.App;

internal sealed class Strings
{
    private ResourceDictionary values = new();
    public string Language { get; private set; } = "en";
    public void Select(string language)
    {
        Language = language == "auto"
            ? CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru" ? "ru" : "en" : language;
        if (Language is not ("ru" or "en")) Language = "en";
        values = new ResourceDictionary { Source = new Uri($"/HiddifyGuard;component/Resources/Strings.{Language}.xaml", UriKind.Relative) };
    }
    public string this[string key] => values[key] as string ?? throw new InvalidOperationException($"Missing UI string: {key}");
}
