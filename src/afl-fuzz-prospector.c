#include "afl-fuzz.h"
#include <math.h>

/* used in afl-fuzz-one */
void update_focused_targets(afl_state_t *afl) {
  // initialize
  if (unlikely(!afl->reach_bits_count)) return;
  if (unlikely(!afl->focused_targets)) {
    afl->focused_targets =
        ck_alloc(sizeof(u32) * VMAP_COUNT);  // only store top 20% target
  } else {
    // If it's already allocated, free the memory before reallocating.
    ck_free(afl->focused_targets);
    afl->focused_targets = ck_alloc(sizeof(u32) * VMAP_COUNT);
  }

  /* update focused targets based on valuable target*/
  add_target_group_into_focused(afl);
  // write_focused_targets_log(afl);
}
void add_target_group_into_focused(afl_state_t *afl) {
  Targets res;
  // if (afl->disable_priority_choice != DISABLE_TARGET) {
  //   afl->focused_targets_count = 0;
  //   afl->skip_intra_func = 0;
  //   res = get_func_target_group(afl->valuable_function);
  // } else {
  afl->focused_targets_count = 0;
  afl->valuable_function = FUNC_SIZE;
  afl->skip_intra_func = 0;
  ACTF("begin obtain target group, where valuable target is %d",
       afl->valuable_target );
  res = get_target_group(afl->valuable_target);
  afl->valuable_function = get_funcid(afl->valuable_target);
  //}
  afl->focused_targets_count = res.size;
  afl->remain_focused_targets_count = afl->focused_targets_count;
  ACTF(" target group size is %ld",res.size);
  for (u32 i = 0; i < res.size; i++) {
    afl->focused_targets[i] = res.targets[i];
    afl->focused_count[res.targets[i]] += 1;
    if (afl->reach_bits_count) {
      if (res.targets[i] < VMAP_COUNT &&
          afl->reach_bits_count[res.targets[i]]) {
        afl->remain_focused_targets_count--;
      }
    }
  }
 
  free_target_group(res);
}

/*
  1. cal_init_seed_score
  2. update_score_determinstic
  3. update_score_havoc
  4.
*/
/* update byte score for group of 4 bytes at the same time */
static inline void update_byte_score_havoc(afl_state_t *afl,
                                           u32         *one_group_byte_score) {
  if (afl->fish_seed_selection == INTER_FUNC_EXPLORE ||
      afl->fish_seed_selection == INTRA_FUNC_EXPLORE) {
    if ((afl->reach_focused_function && afl->has_new_paths)) {
      if (*one_group_byte_score != 0xffffffff)  // don't overflow
        *one_group_byte_score += 0x01010101;    // each byte adds one
    }
  }
  if (afl->fish_seed_selection == TARGET_EXPLOIT) {
    if (afl->has_new_paths && afl->reach_focused_targets) {
      if (*one_group_byte_score != 0xffffffff)  // don't overflow
        *one_group_byte_score += 0x01010101;    // each byte adds one
    }
    if (!afl->reach_focused_function)  // miss focused function
    {
      if (*one_group_byte_score != 0)         // don't underflow
        *one_group_byte_score -= 0x01010101;  // each byte minus one
    }
  }
}
/* update byte score for group of 4 bytes at the same time */
static inline void update_byte_score_deterministic(afl_state_t        *afl,
                                                   struct queue_entry *q,
                                                   s32 start_pos, s32 end_pos) {
  u32 *group_byte_score = (u32 *)q->byte_score;
  u32  group_start_pos = (u32)start_pos / ACO_GROUP_SIZE;
  u32  group_end_pos = (u32)end_pos / ACO_GROUP_SIZE;
  u32  group_max_pos = q->align_len / ACO_GROUP_SIZE;

  if (group_start_pos == group_end_pos) {
    if (group_start_pos < group_max_pos)
      update_byte_score_havoc(afl, group_byte_score + group_start_pos);
  } else {
    if (group_start_pos < group_max_pos)
      update_byte_score_havoc(afl, group_byte_score + group_start_pos);
    if (group_end_pos < group_max_pos)
      update_byte_score_havoc(afl, group_byte_score + group_end_pos);
  }
}
/* determine if a seed reach the focused target , used in byte schedule of
 * exploitation */
bool reach_focused_target(afl_state_t *afl) {
  // traverse the focused target
  for (u32 i = 0; i < afl->focused_targets_count; i++) {
    u32 focused_target = afl->focused_targets[i];
    if (focused_target < VMAP_COUNT && afl->reach_bits_count[focused_target]) {
      return true;
    }
  }
  return false;
}

double ratio_of_time(afl_state_t *afl, u64 last_new_time) {
  if (afl->remain_focused_targets_count == 0) return 1;
  double prob = (get_cur_time() - last_new_time) / SHORT_TIME_LIMIT /
                (log10(1 + afl->remain_focused_targets_count));
  return prob;
}

double ratio_of_reachable_func(afl_state_t *afl) {
  double prob = 0.0;
  u32    reached = 0;
  if (!afl->focused_targets_count || !afl->focused_targets) return 0;
  size_t     reachable_count;
  const u32 *reachable_funcs =
      get_reachable_functions(afl->valuable_function, &reachable_count);
  // OKF("function %d has %ld reachable function\n the reachable function list
  // below\b", afl->valuable_function, reachable_count);
  for (u32 i = 0; i < reachable_count; i++) {
    u32 funcid = reachable_funcs[i];
    // OKF("%d\n", funcid);
    if (reach_function(afl, funcid)) { reached++; }
  }

  if (reach_function(afl, afl->valuable_function)) reached++;
  prob = (double)reached / (reachable_count + 1);
  return prob;
}
double ratio_of_reached_focused_target(afl_state_t *afl) {
  // traverse the focused target
  double prob = 0.0;
  u32    reached = 0;
  if (!afl->focused_targets_count || !afl->focused_targets ||
      !afl->reach_bits_count)
    return 0;
  for (u32 i = 0; i < afl->focused_targets_count; i++) {
    u32 focused_target = afl->focused_targets[i];
    if (focused_target < VMAP_COUNT && afl->reach_bits_count[focused_target]) {
      reached++;
    }
  }
  prob = (double)reached / afl->focused_targets_count;
  return prob;
}

double ratio_of_triggered_focused_target(afl_state_t *afl) {
  double prob = 0.0;
  u32    triggered = 0;
  for (u32 i = 0; i < afl->focused_targets_count; i++) {
    u32 focused_target = afl->focused_targets[i];
    if (focused_target < VMAP_COUNT &&
        afl->trigger_bits_count[focused_target]) {
      triggered++;
    }
  }
  prob = (double)triggered / afl->focused_targets_count;
  return prob;
}

/* determine if a seed reach the focused function , used in byte schedule of
 * exploration, modified from AFLChurn (https://github.com/aflchurn/aflchurn)  */
bool reach_function(afl_state_t *afl, u32 funcid) {
  if (afl->shm.fish_map[funcid]) {
    return true;
  } else {
    return false;
  }
}

void cal_init_seed_score(afl_state_t *afl, u8 byte_offset) {
  if (unlikely(!afl->queue_cur->byte_score)) return;

  update_byte_score_deterministic(afl, afl->queue_cur, afl->stage_cur_byte,
                                  afl->stage_cur_byte + byte_offset);
}

void expire_old_score(afl_state_t *afl, struct queue_entry *q) {
  // if (!(total_aco_updates % ACO_FREQENCY)){
  if (!rand_below(afl, q->len)) {
    if (q->byte_score) {
      for (u32 i = 0; i < q->align_len; i++) {
        /* gravitate to INIT_BYTE_SCORE */
        // just drop the fractional part
        if (q->byte_score[i] > MIN_BYTE_SCORE &&
            q->byte_score[i] < INIT_BYTE_SCORE) {
          q->byte_score[i]++;
        } else if (q->byte_score[i] > INIT_BYTE_SCORE &&
                   q->byte_score[i] < MAX_BYTE_SCORE) {
          q->byte_score[i]--;
        } else {
          // values in [MIN_BYTE_SCORE, MAX_BYTE_SCORE] will not change using
          // this calculation
          q->byte_score[i] = q->byte_score[i] * ACO_COEF + ACO_GRAV_BIAS;
        }
      }
    }
  }
}
void update_fitness_in_havoc(afl_state_t *afl, struct queue_entry *q,
                             u8 *seed_mem, u8 *cur_input_mem,
                             u32 cur_input_len) {
  if (q->len != cur_input_len) return;

  if (unlikely(!q->byte_score)) return;
  /* if one byte in a group with the size group_size changes the fitness,
      other bytes in the group have the same change.
   */
  u32  i = q->align_len / ACO_GROUP_SIZE;
  u32 *group_seed = ((u32 *)seed_mem);
  u32 *group_cur_input = ((u32 *)cur_input_mem);
  u32 *group_byte_score = (u32 *)(q->byte_score);

  while (i--) {
    if ((*(group_seed++)) != (*(group_cur_input++))) {
      update_byte_score_havoc(afl, group_byte_score);
    }
    group_byte_score++;
  }
}

static inline u32 select_one_byte(afl_state_t *afl, struct queue_entry *q,
                                  u32 cur_input_len) {
  // randomly select an aliased seed
  u32 s = rand_below(afl, cur_input_len);
  // generate the next percent
  double p = (double)rand_below(afl, 0xFFFFFFFF) / 0xFFFFFFFE;
  return (p < q->alias_prob[s] ? s : q->alias_table[s]);
}

void create_byte_alias_table(afl_state_t *afl, struct queue_entry *q) {
  u32 n = q->len, i = 0, a, g;

  if (!afl->byte_prob_norm_buf) {
    afl->byte_prob_norm_buf = (u8 *)ck_alloc(n * sizeof(double));
    afl->byte_out_scratch_buf = (u8 *)ck_alloc(n * sizeof(int));
    afl->byte_in_scratch_buf = (u8 *)ck_alloc(n * sizeof(int));
    afl->aco_max_seed_len = n;
  } else if (afl->aco_max_seed_len < n) {
    afl->byte_prob_norm_buf =
        (u8 *)ck_realloc((void *)afl->byte_prob_norm_buf, n * sizeof(double));
    afl->byte_out_scratch_buf =
        (u8 *)ck_realloc((void *)afl->byte_out_scratch_buf, n * sizeof(int));
    afl->byte_in_scratch_buf =
        (u8 *)ck_realloc((void *)afl->byte_in_scratch_buf, n * sizeof(int));
    afl->aco_max_seed_len = n;
  }

  double *P = (double *)afl->byte_prob_norm_buf;
  int    *S = (int *)afl->byte_out_scratch_buf;
  int    *L = (int *)afl->byte_in_scratch_buf;

  if (!P || !S || !L) { FATAL("could not aquire memory for alias table"); }
  memset(q->alias_table, 0, n * sizeof(u32));
  memset(q->alias_prob, 0, n * sizeof(double));

  u32 sum = 0;

  for (i = 0; i < n; i++) {
    sum += q->byte_score[i];
  }

  if (sum == 0) {
    for (i = 0; i < n; i++) {
      q->alias_prob[i] = 1.0;
    }
    return;
  }

  for (i = 0; i < n; i++) {
    P[i] = (double)(q->byte_score[i] * n) / sum;
  }

  int nS = 0, nL = 0, s;
  for (s = (s32)n - 1; s >= 0; --s) {
    if (P[s] < 1) {
      S[nS++] = s;

    } else {
      L[nL++] = s;
    }
  }

  while (nS && nL) {
    a = S[--nS];
    g = L[--nL];
    q->alias_prob[a] = P[a];
    q->alias_table[a] = g;
    P[g] = P[g] + P[a] - 1;
    if (P[g] < 1) {
      S[nS++] = g;

    } else {
      L[nL++] = g;
    }
  }

  while (nL)
    q->alias_prob[L[--nL]] = 1;

  while (nS)
    q->alias_prob[S[--nS]] = 1;
}

/* select a way to choose mutated bytes */
u32 URfitness(afl_state_t *afl, u32 input_len) {
  struct queue_entry *q = afl->queue_cur;
  if (afl->use_byte_fitness && (q->len == input_len)) {
    return select_one_byte(afl, q, input_len);
  } else {
    return rand_below(afl, input_len);
  }
}

void destroy_alias_buf(afl_state_t *afl) {
  ck_free(afl->byte_prob_norm_buf);
  ck_free(afl->byte_out_scratch_buf);
  ck_free(afl->byte_in_scratch_buf);
}

/* used in afl-fuzz-run */
void update_fishfuzz_states(afl_state_t *afl, u8 *fish_map) {
  // initialization
  if (unlikely(!afl->trigger_bits_count)) {
    afl->trigger_bits_count = ck_alloc(sizeof(u32) * VMAP_COUNT);
  }
  if (unlikely(!afl->reach_bits_count)) {
    afl->reach_bits_count = ck_alloc(sizeof(u32) * VMAP_COUNT);
  }
  if (unlikely(!afl->unique_reach_bits_count)) {
    afl->unique_reach_bits_count = ck_alloc(sizeof(u32) * VMAP_COUNT);
  }
  afl->reach_focused_targets = 0;
  afl->reach_new_targets = 0;

  if (unlikely(!afl->reach_target_seq_set)) {
    afl->reach_target_seq_set = kh_init(sequence_set);
  }

  u8 *targets_map = fish_map + FUNC_SIZE;

  u64 target_seq_sum =
      hash64(targets_map, afl->target_count / 4 + 1, HASH_CONST);
  khint64_t target_seq_iter =
      kh_put(sequence_set, afl->reach_target_seq_set, target_seq_sum,
             &afl->is_unique_target_seq);
  for (u32 i = 0; i < VMAP_SIZE; i++) {
    if (unlikely(targets_map[i])) {
      for (u32 k = 0; k < 4; k++) {
        // printf("trigger %x, %x, %x\n", i, k, i * 4 + k);
        if (targets_map[i] & (1 << (k * 2))) {
          if (!afl->trigger_bits_count[i * 4 + k]) {
            afl->last_trigger_time = get_cur_time();
            afl->current_targets_triggered++;
            /* udpate if execution trigger focused targets */
            for (u32 j = 0; j < afl->focused_targets_count; j++) {
              if (afl->focused_targets[j] == i * 4 + k) {
                afl->last_trigger_focused_time = get_cur_time();
                break;
              }
            }
          }

          afl->trigger_bits_count[i * 4 + k]++;
        }
        if (targets_map[i] & (1 << (k * 2 + 1))) {
          // printf("reach %x, %x, %x\n", i, k, i * 4 + k);
          // if reach new targets
          if (!afl->reach_bits_count[i * 4 + k]) {
            afl->last_reach_time = get_cur_time();
            afl->current_targets_reached++;
            afl->reach_new_targets = 1;
            /* udpate if execution reach focused targets */
            if (!afl->reach_focused_targets) {
              for (u32 j = 0; j < afl->focused_targets_count; j++) {
                if (afl->focused_targets[j] == i * 4 + k) {
                  afl->reach_focused_targets = 1;
                  afl->last_reach_focused_time = get_cur_time();
                  afl->remain_focused_targets_count--;
                  break;
                }
              }
            }
          }
          if (afl->is_unique_target_seq) {
            afl->unique_reach_bits_count[i * 4 + k]++;
          }

          afl->reach_bits_count[i * 4 + k]++;
        }
      }
    }
  }

  if (!afl->focused_targets_count) {
    /* update if execution reach focused function*/
    if (reach_function(afl, afl->valuable_function)) {
      afl->reach_focused_function = 1;
    } else {
      afl->reach_focused_function = 0;
    }
  }

}

u32 calculate_target_score(afl_state_t *afl, u32 i) {
  double normalized_metric = 0;
  double metric;

  metric = 100 * afl->unique_reach_bits_count[i] /
           (afl->target_initial_priority[i] + 1);

  if (afl->max_target_priority == afl->min_target_priority) {
    normalized_metric = 100 + afl->focused_count[i] * 100;
  } else {
    normalized_metric =
        100 * (metric - afl->min_target_priority) /
            (afl->max_target_priority - afl->min_target_priority) +
        afl->focused_count[i] * 100;
  }

  return (u32)normalized_metric;
}
