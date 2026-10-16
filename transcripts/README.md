# Transcripts

Every agent run from the episode, verbatim: the console output (`.txt`) and the harness log (`.jsonl`, one line per step with the model's action and the harness's result).

| run | mode | outcome |
|---|---|---|
| `run_zero_1` | zero | 0 differences at step 16, then stopped as "stuck" at step 18 by a harness bug (re-reading an edited file). Fixed in `_repeating()` |
| `run_zero_2` | zero | done in 20 steps. 33 differences, one rewrite, 0. Restored `age: 1e21` |
| `run_review_1` | review | exit 4 after 21 steps. 9 differences, 2 left on purpose, written up in `review/corpus-diffs.md` |

`replay_ep23_migration.txt` is the corpus replayed against last episode's merged migration: 33 different answers.
