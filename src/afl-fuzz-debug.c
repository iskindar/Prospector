#include "afl-fuzz.h"

/* log file for fishfuzz */

void write_fishfuzz_log(afl_state_t *afl, u8 prev_mode, u8 current_mode) {
  if (!afl->fish_debug_log) {
    afl->fish_debug_log = alloc_printf("%s/fish_debug.log", afl->out_dir);
    afl->fish_debug_fd = fopen(afl->fish_debug_log, "w");
  }

  afl->last_log_time = get_cur_time();

  if (!afl->virgin_funcs) return;
  u32 func_cov = 0;
  for (u32 i = 0; i < FUNC_SIZE; i++) {
    if (afl->virgin_funcs[i]) func_cov += 1;
  }

  u8 *prev_mode_s, *current_mode_s;
  switch (prev_mode) {
    case INTRA_FUNC_EXPLORE:
      prev_mode_s = (u8 *)"ORIGINAL";
      break;
    case INTER_FUNC_EXPLORE:
      prev_mode_s = (u8 *)"EXPLORE";
      break;
    default:
      prev_mode_s = (u8 *)"EXPLOIT";
  }

  switch (current_mode) {
    case INTRA_FUNC_EXPLORE:
      current_mode_s = (u8 *)"ORIGINAL";
      break;
    case INTER_FUNC_EXPLORE:
      current_mode_s = (u8 *)"EXPLORE";
      break;
    default:
      current_mode_s = (u8 *)"EXPLOIT";
  }

  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->fish_debug_fd,
          "[%02lld:%02lld:%02lld] %s->%s : round %lld, fav %d/%d/%d, %d/%d/%d "
          "of %d are fuzzed, cov : %d/%d, violation : %d/%d.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, prev_mode_s, current_mode_s,
          afl->queue_cycle, afl->pending_favored, afl->queued_retryed,
          afl->queued_favored, afl->queued_fuzzed_favored,
          afl->queued_fuzzed_non_favored, afl->queued_fuzzed_retryed,
          afl->queued_items, func_cov,
          count_non_255_bytes(afl, afl->virgin_bits),
          afl->current_targets_reached, afl->current_targets_triggered);
}

/*
void write_exploit_log(afl_state_t *afl, u32 exploit_threshould) {

  if (!afl->exploit_debug_log) {

    afl->exploit_debug_log = alloc_printf("%s/exploit_debug.log", afl->out_dir);
    afl->exploit_debug_fd = fopen(afl->exploit_debug_log, "w");

  }

  u64 current_ms = get_cur_time() - afl->start_time;

  for (u32 i = 0; i < VMAP_COUNT; i ++) {

    if (afl->top_rated_exploit[i] && afl->reach_bits_count[i] <
exploit_threshould) {

      fprintf(afl->exploit_debug_fd, "[%02lld:%02lld:%02lld] update seed %s as
favored for %d\n", current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
(current_ms / 1000) % 60, afl->top_rated_exploit[i]->fname, i);

    }

  }


}
*/

void write_cull_log(afl_state_t *afl) {
  if (!afl->cull_debug_log) {
    afl->cull_debug_log = alloc_printf("%s/cull_debug.log", afl->out_dir);
    afl->cull_debug_fd = fopen(afl->cull_debug_log, "w");
  }

  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->cull_debug_fd,
          "[%02lld:%02lld:%02lld] origin takes %lld, explore takes %lld, "
          "exploit takes %lld, others %lld, update explore %lld.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, afl->log_cull_origin_time,
          afl->log_cull_explore_time, afl->log_cull_exploit_time,
          afl->log_cull_other_time, afl->log_update_explore_time);
}

void write_seed_selection_log(afl_state_t *afl, u8 skip_fuzz) {
  if (!afl->seed_selec_log) {
    afl->seed_selec_log = alloc_printf("%s/seed_selec.log", afl->out_dir);
    afl->seed_selec_fd = fopen(afl->seed_selec_log, "w");
  }

  u64 current_ms = get_cur_time() - afl->start_time;

  fprintf(
      afl->seed_selec_fd,
      "[%02lld:%02lld:%02lld] %s fuzz %s seed %d, now in %s mode.\n",
      current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
      (current_ms / 1000) % 60,
      (skip_fuzz == 0) ? (u8 *)"finish" : (u8 *)"skip",
      afl->queue_cur->favored ? (u8 *)"favored" : (u8 *)"non-favored",
      afl->current_entry,
      (afl->fish_seed_selection == INTER_FUNC_EXPLORE)
          ? (u8 *)"explore"
          : (afl->fish_seed_selection == INTRA_FUNC_EXPLORE ? (u8 *)"origin"
                                                            : (u8 *)"exploit"));
}

void write_exploit_log(afl_state_t *afl) {
  if (!afl->exploit_log) {
    afl->exploit_log = alloc_printf("%s/exploit.log", afl->out_dir);
    afl->exploit_fd = fopen(afl->exploit_log, "w");
  }
  if (!afl->reach_bits_count) return;

  u64 total_reach_cnt = 0, total_trigger_cnt = 0;
  for (u32 i = 0; i < VMAP_COUNT; i++) {
    if (afl->reach_bits_count[i]) total_reach_cnt += afl->reach_bits_count[i];
    if (afl->trigger_bits_count[i])
      total_trigger_cnt += afl->trigger_bits_count[i];
  }

  u64 current_ms = get_cur_time() - afl->start_time;
  u64 avg_reach = (afl->current_targets_reached)
                      ? total_reach_cnt / afl->current_targets_reached
                      : 0,
      avg_trigger = (afl->current_targets_triggered)
                        ? total_trigger_cnt / afl->current_targets_triggered
                        : 0;

  fprintf(afl->exploit_fd,
          "[%02lld:%02lld:%02lld] bug threshould %d, retry threshould "
          "%lld/%lld/%lld.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, afl->exploit_threshould, avg_trigger,
          avg_reach, afl->fsrv.total_execs / afl->current_targets_reached);
}

void write_develop_log(afl_state_t *afl) {
  if (!afl->dev_log) {
    afl->dev_log = alloc_printf("%s/dev.log", afl->out_dir);
    afl->dev_fd = fopen(afl->dev_log, "w");
  }
  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->dev_fd,
          "[%02lld:%02lld:%02lld] now we have %d func and %d bbs covered, %d "
          "sanitizer targets reached and %d triggered .\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, afl->current_func_covered,
          count_non_255_bytes(afl, afl->virgin_bits),
          afl->current_targets_reached, afl->current_targets_triggered);
}

void write_reach_log(afl_state_t *afl, u32 target_seq_id) {
  if (!afl->reach_log) {
    afl->reach_log = alloc_printf("%s/reach.log", afl->out_dir);
    afl->reach_fd = fopen(afl->reach_log, "w");
  }
  u64 current_ms = get_cur_time() - afl->start_time;

  fprintf(
      afl->reach_fd, "[%02lld:%02lld:%02lld]:[%d]:", current_ms / 1000 / 3600,
      (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, target_seq_id);
  for (u8 j = 0; j < TARGET_SEQ_LENGTH; j++) {
    fprintf(afl->reach_fd, "%d ",
            afl->reach_target_seqs[target_seq_id * TARGET_SEQ_LENGTH + j]);
  }
  fprintf(afl->reach_fd, "\n");
}

void write_collection_log(afl_state_t *afl, u32 target_id, s32 byte_start,
                          s32 byte_end) {
  if (!afl->collection_log) {
    afl->collection_log = alloc_printf("%s/collection.log", afl->out_dir);
    afl->collection_fd = fopen(afl->collection_log, "w");
  }
  u64 current_ms = get_cur_time() - afl->start_time;

  fprintf(afl->collection_fd, "[%02lld:%02lld:%02lld] target [%d]: [%d,%d] \n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, target_id, byte_start, byte_end);
}

void write_byte_score_log(afl_state_t *afl) {
  if (!afl->byte_score_log) {
    afl->byte_score_log = alloc_printf("%s/byte.log", afl->out_dir);
    afl->byte_score_fd = fopen(afl->byte_score_log, "w");
  }

  // for (i = 0; i < afl->queued_items; i++) {
  //   struct queue_entry *q;
  //   q = afl->queue_buf[i];
  //   if (q->byte_score) {
  //     for (u32 j = 0; j < q->len; j++) {
  //       fprintf(afl->byte_score_fd, "%d, ", q->byte_score[j]);
  //     }
  //     fprintf(afl->byte_score_fd, "\n");
  //   }
  // }
  if(afl->queue_cur->byte_score){
    for (u32 j = 0; j < afl->queue_cur->len; j++) {
        if(afl->queue_cur->byte_score[j] != INIT_BYTE_SCORE){
          fprintf(afl->byte_score_fd, "%d, ", afl->queue_cur->byte_score[j]);
        }
      }
  }
  fprintf(afl->byte_score_fd, "\n-------------------------------\n");
}
void write_focused_targets_log(afl_state_t * afl){
  if(!afl->focused_targets_log){
    afl->focused_targets_log = alloc_printf("%s/focus.log", afl->out_dir);
    afl->focused_targets_fd = fopen(afl->focused_targets_log, "w");
  }
  u32 i ;
  u64 current_ms = get_cur_time() - afl->start_time;
  
  if(afl->disable_priority_choice == DISABLE_TARGET){
    fprintf(afl->focused_targets_fd, "[%02lld:%02lld:%02lld] exploit threshould :%d \n", current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, afl->exploit_threshould);
  }else{
    fprintf(afl->focused_targets_fd, "[%02lld:%02lld:%02lld] exploit threshould :%d \nfocus on target %d of %d \n", current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, afl->exploit_threshould, afl->valuable_target,afl->valuable_function);
  }
  
  for ( i = 0; i < afl->focused_targets_count; i++)
  {
    fprintf(afl->focused_targets_fd, "%d, ", afl->focused_targets[i]);
  }
  // print whether to reach the focused function
  if(afl->last_update_focused_target_time){
    if(afl->last_func_focused_time > afl->last_update_focused_target_time){
      fprintf(afl->focused_targets_fd, "\n During focusing time, reach the focused function %d, costing %lld\n", afl->valuable_function,(afl->last_func_focused_time-afl->last_update_focused_target_time)/1000);
    }
    //print the ratio of the reached focused target
    fprintf(afl->focused_targets_fd, "\n During focusing time, the ratio of reached reachable function of focused function %lf\n", ratio_of_reachable_func(afl));
    fprintf(afl->focused_targets_fd, "\n During focusing time, the ratio of reached focused target %lf\n", ratio_of_reached_focused_target(afl));
    fprintf(afl->focused_targets_fd, "\n During focusing time, the ratio of triggered focused target %lf\n", ratio_of_triggered_focused_target(afl));
    fprintf(afl->focused_targets_fd, "\n current stage is %d,remain %d\n", afl->fish_seed_selection,afl->remain_focused_targets_count);
    if(afl->fish_seed_selection == INTER_FUNC_EXPLORE){
        fprintf(afl->focused_targets_fd, "\n ratio of time %lf\n",ratio_of_time(afl,afl->last_func_focused_time));
    }else if(afl->fish_seed_selection == INTRA_FUNC_EXPLORE){
        fprintf(afl->focused_targets_fd, "\n ratio of time %lf\n",ratio_of_time(afl,afl->last_reach_focused_time));
    }else if(afl->fish_seed_selection == TARGET_EXPLOIT){
        fprintf(afl->focused_targets_fd, "\n ratio of time %lf\n",ratio_of_time(afl,afl->last_trigger_focused_time));
    }else
    {
      fprintf(afl->focused_targets_fd, "\n current stage does not exist\n");
    }
    //write_fishfuzz_log(afl, afl->fish_seed_selection,afl->fish_seed_selection);
  }
  fprintf(afl->focused_targets_fd, "\n");
  
  afl->last_update_focused_target_time = get_cur_time() - afl->start_time;
}
void write_target_priority_log(afl_state_t * afl){
  if(!afl->target_priority_log){
    afl->target_priority_log = alloc_printf("%s/dyn_priority.log", afl->out_dir);
    afl->target_priority_fd = fopen(afl->target_priority_log, "w");
  }

  u32 i ;
  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->focused_targets_fd, "[%02lld:%02lld:%02lld] exploit threshould :%d \nfocus on target %d of %d \n", current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, afl->exploit_threshould, afl->valuable_target,afl->valuable_function);
  
  
  for ( i = 0; i < afl->focused_targets_count; i++)
  {
    fprintf(afl->focused_targets_fd, "%d, ", afl->focused_targets[i]);
  }
   fprintf(afl->focused_targets_fd, "\n");
}


