# Translation style: Jikkyou Powerful Pro Yakyuu 15, Japanese to English

Method borrowed from the `srt-pipeline` repo (`docs/ja-to-en.md`): fix the voices and the recurring
terms in a context file first, then translate scene by scene against it.
Sections marked **(proposal)** are not agreed yet. Settle them before translating in bulk.

## Principle

Pawapuro is a Japanese institution. The English should read as a Japanese game in English, not as
an American baseball game. Keep the setting, the social relations and the way people talk. Do not
swap in American equivalents, and do not footnote. Faithful, but never stiff, cute or over the top.

Priorities, highest first:
1. What the character is trying to do or feel in the line.
2. The character's voice (register, tics, dialect).
3. Natural English.
4. The facts of the line.
5. Literal wording. Sentence-final particles become tone, not tag questions.

## Fixed rules

- **Names:** family name first (Yabe Akio). Hepburn without macrons (Koshien, Tokyo, senpai).
- **Honorifics:** keep `-san`, `-kun`, `-chan`, `-senpai`, `-sensei`. They carry the relationships.
  A character who drops them is being rude or close, and that must stay visible.
- **Japanese terms that stay as they are:** Koshien, senpai, kohai, bento, and other words an
  English reader of a Japanese game knows or can pick up. Add to the glossary as they come up.
- **Setting:** yen, km/h, metres, school years, company ranks (bucho, shacho) stay Japanese.
  No dollars, mph or American league terms.
- **Baseball terms:** standard English baseball words for the game itself (strikeout, bunt,
  hit by pitch for デッドボール). Japan-specific institutions keep their identity (Koshien,
  the draft, industrial-league ball for 社会人野球).
- **Voices are locked.** Once a character has a register and a tic, they never change unless the
  story makes them. Give every main character an entry below with one example line before
  translating their scenes.
- **Recurring phrases are locked.** One English rendering each, listed under Running beats.

## Dialect and speech quirks (proposal)

- **Kansai-ben:** do not map it to an English regional accent (no Southern, Cockney or Scots).
  Carry it with rhythm and attitude: blunt, quick, warm, fond of a comeback. Keep a small set of
  iconic words in romaji where the Japanese has them and the meaning is clear from the scene
  (`Akan!`, `Nande ya nen!`, `Honma ni?`, `Maido!`, `-han`, `ookini`). A light touch: a marker every
  few lines is enough to hear the voice. Never invented spellings ("Ah dunno").
- **Verbal tics (語尾):** keep the tic, in a form that reads naturally at the end of an English
  sentence, and use it as often as the Japanese does only where it does not grate.
  Yabe's `でやんす`: keep it as `-yansu` (for example "That was expensive-yansu.").
  Alternative: drop the suffix and give him a fixed underling voice ("this humble Yabe").
- **First-person words:** オレ, ボク, オイラ, ワシ, 私 all say something. Show it through register
  (rough, boyish, folksy, old man, polite), not through odd pronouns.
- **Old men's `じゃ` / `のう`:** plain, slightly old-fashioned English. No "ye olde".
- **Sound effects:** translate the sense, keep them short ("(Knock knock)").

## Characters

Template (from srt-pipeline). Fill in from the script before translating a character's scenes.

### 矢部明雄 / Yabe Akio [MAIN]
- Honorifics: calls the player `-kun`.
- Contractions: YES
- Register: cheerful sidekick, otaku, self-deprecating. Calls himself オイラ.
- Verbal tics: ends sentences with でやんす (see proposal above).
- Example: to be fixed once the tic is agreed.

### 主人公 / the player [MAIN]
- Contractions: YES
- Register: earnest, a bit rough (オレ), polite to superiors at work.
- Example: "I'll get results in that time and go pro, no matter what!"

## Running beats (locked renderings)

| Japanese | English |
|---|---|
| 株式会社パワフル | Pawafuru Corp. |
| 社会人野球 | industrial-league ball (proposal; "company baseball" in the opening for now) |

## Glossary

| Japanese | English | Notes |
|---|---|---|
| サクセス | Success Mode | |
| 甲子園 | Koshien | |
| 親父 / せがれ | Dad, "old man" / son | father and son in the opening |

## Limits set by the game

- 34 letters per line, 2 lines per box (main dialogue box). The build warns about longer lines.
- One entry per text run. Where a sentence is split into several runs on one line (colour change,
  inserted name), give the earlier run an even number of letters.
- Inserted player names are still Japanese: do not write sentences that depend on an English name.
