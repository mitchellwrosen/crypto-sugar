module Main where

import Options.Applicative


main :: IO ()
main =
  join (customExecParser parserPrefs (info parser (progDesc description)))

  where
    description :: [Char]
    description =
      "Description"

    parserPrefs :: ParserPrefs
    parserPrefs =
      ParserPrefs
        { prefMultiSuffix = ""
        , prefDisambiguate = False
        , prefShowHelpOnError = True
        , prefShowHelpOnEmpty = True
        , prefBacktrack = True
        , prefColumns = 80
        }

parser :: Parser (IO ())
parser =
  hsubparser
    (fold
      [ command "foo" (info fooParser (progDesc "Foo description"))
      ])

fooParser :: Parser (IO ())
fooParser =
  pure (pure ())
